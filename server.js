#!/usr/bin/env node
'use strict';

const net = require('node:net');
const dgram = require('node:dgram');
const dnsPromises = require('node:dns').promises;
const dns = require('node:dns');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');

// ==========================================
// 1. ENVIRONMENT & PORT SETTINGS
// ==========================================
const MAIN_PORT = parseInt(process.env.PORT, 10) || 8080;
let parsedProxyPort = parseInt(process.env.PROXY_PORT, 10) || 8081;
if (parsedProxyPort === MAIN_PORT) {
  parsedProxyPort = MAIN_PORT === 8080 ? 8081 : 8080;
}
const EXTRA_TCP_PORT = parsedProxyPort;

const RAILWAY_PUBLIC_DOMAIN = process.env.RAILWAY_PUBLIC_DOMAIN || '';
const TCP_DOMAIN = process.env.RAILWAY_TCP_PROXY_DOMAIN || '';
const TCP_PORT = process.env.RAILWAY_TCP_PROXY_PORT || '';
const DB_PATH = path.resolve(process.env.DATA_DIR || './', 'proxy_data.json');

const UDP_ENDPOINT_URL = RAILWAY_PUBLIC_DOMAIN 
  ? `wss://${RAILWAY_PUBLIC_DOMAIN}:443` 
  : `ws://127.0.0.1:${MAIN_PORT}`;

// ==========================================
// 2. STATE & CONFIGURATION
// ==========================================
const proxyUsers = new Map();
let PROXY_AUTH_MODE = 'NONE';

let RAW_TCP_CONFIG = {
  enabled: true,
  defaultTargetHost: 'speed.cloudflare.com',
  defaultTargetPort: 443
};

// Default langsung di-set ke Cloudflare UDP untuk latensi terendah
let DNS_CONFIG = {
  mode: 'UDP',
  activeName: 'Cloudflare UDP (1.1.1.1:53)',
  dohUrl: 'https://cloudflare-dns.com/dns-query',
  udpServer: '1.1.1.1',
  udpPort: 53
};

const PRESETS = {
  'cf-udp': { name: 'Cloudflare UDP 1.1.1.1:53 (Paling Cepat)', type: 'UDP', host: '1.1.1.1', port: 53 },
  'google-udp': { name: 'Google UDP 8.8.8.8:53 (Bagus YouTube)', type: 'UDP', host: '8.8.8.8', port: 53 },
  'cf-doh': { name: 'Cloudflare DoH (Official)', type: 'DOH', url: 'https://cloudflare-dns.com/dns-query' },
  'google-doh': { name: 'Google DoH', type: 'DOH', url: 'https://dns.google/dns-query' },
  'quad9-udp': { name: 'Quad9 UDP (9.9.9.9:53)', type: 'UDP', host: '9.9.9.9', port: 53 },
  'quad9-doh': { name: 'Quad9 DoH (Security)', type: 'DOH', url: 'https://dns.quad9.net/dns-query' },
  'adguard-doh': { name: 'AdGuard DoH (Adblock)', type: 'DOH', url: 'https://dns.adguard-dns.com/dns-query' }
};

function loadData() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf-8');
      const data = JSON.parse(raw);
      if (data.authMode) PROXY_AUTH_MODE = data.authMode;
      if (data.dnsConfig) DNS_CONFIG = data.dnsConfig;
      if (data.rawTcpConfig) RAW_TCP_CONFIG = { ...RAW_TCP_CONFIG, ...data.rawTcpConfig };
      if (Array.isArray(data.users)) {
        proxyUsers.clear();
        for (const [u, p] of data.users) proxyUsers.set(u, p);
      }
    }
  } catch (err) {
    console.error('[Storage Error] Failed to read database:', err.message);
  }
}

function saveData() {
  try {
    const payload = {
      authMode: PROXY_AUTH_MODE,
      dnsConfig: DNS_CONFIG,
      rawTcpConfig: RAW_TCP_CONFIG,
      users: Array.from(proxyUsers.entries())
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(payload, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Storage Error] Failed to save database:', err.message);
  }
}
loadData();

let PROXY_SERVER_INFO = {
  domain: TCP_DOMAIN,
  port: TCP_PORT,
  ip: '',
  fullProxy: ''
};

function updateRailwayProxyIP() {
  if (TCP_DOMAIN) {
    dns.lookup(TCP_DOMAIN, (err, address) => {
      if (!err && address) {
        PROXY_SERVER_INFO.ip = address;
        PROXY_SERVER_INFO.fullProxy = `${address}:${TCP_PORT}`;
      } else {
        PROXY_SERVER_INFO.ip = TCP_DOMAIN;
        PROXY_SERVER_INFO.fullProxy = `${TCP_DOMAIN}:${TCP_PORT}`;
      }
    });
  } else {
    PROXY_SERVER_INFO.fullProxy = `TCP Proxy Not Set`;
  }
}
updateRailwayProxyIP();
setInterval(updateRailwayProxyIP, 1000 * 60 * 30);

// Proxy Tracker
const activeConnections = new Map();
let connectionIdCounter = 0;
let proxyBytesIn = 0;
let proxyBytesOut = 0;
const dnsCache = new Map();

// UDP Relay Tracker
const UDP_CONFIG = Object.freeze({
  LISTEN_HOST: '0.0.0.0',
  WS_PATH: '/',
  MAX_WS_MESSAGE_BYTES: 8 * 1024 * 1024,
  HANDSHAKE_TIMEOUT_MS: 10000,
  IDLE_TIMEOUT_MS: 300000,
  XUDP_GRACE_MS: 60000,
  MAX_CONNECTIONS: 8192,
  REJECT_UDP_443: false,
});

const UDP_STATS = {
  activeClients: 0,
  totalHandshakes: 0,
  udpPacketsOut: 0,
  udpBytesOut: 0,
  udpPacketsIn: 0,
  udpBytesIn: 0,
  recentLogs: []
};

function addUdpLog(msg) {
  const time = new Date().toLocaleTimeString('id-ID');
  UDP_STATS.recentLogs.unshift(`[${time}] ${msg}`);
  if (UDP_STATS.recentLogs.length > 60) UDP_STATS.recentLogs.pop();
}

// ==========================================
// 3. OPTIMIZED FORMATTER & DNS RESOLVER
// ==========================================
function formatDynamicBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  if (i === 0) return bytes + ' B';
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function resolveDomain(hostname) {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  // Cache dipertahankan selama 1 jam untuk mencegah jeda resolve berulang
  if (cached && (now - cached.time < 1000 * 60 * 60)) return cached.ip;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname;

  if (DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer) {
    try {
      const resolver = new dns.Resolver();
      resolver.setServers([`${DNS_CONFIG.udpServer}:${DNS_CONFIG.udpPort || 53}`]);
      return await new Promise((resolve, reject) => {
        resolver.resolve4(hostname, (err, addresses) => {
          if (!err && addresses && addresses.length > 0) {
            dnsCache.set(hostname, { ip: addresses[0], time: now });
            resolve(addresses[0]);
          } else reject(err);
        });
      });
    } catch (_) {}
  }

  if (DNS_CONFIG.mode === 'DOH') {
    try {
      const url = new URL(DNS_CONFIG.dohUrl);
      url.searchParams.set('name', hostname);
      url.searchParams.set('type', 'A');
      const res = await fetch(url.toString(), {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(1500)
      });
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        const aRecord = data.Answer.find(ans => ans.type === 1);
        if (aRecord && aRecord.data) {
          dnsCache.set(hostname, { ip: aRecord.data, time: now });
          return aRecord.data;
        }
      }
    } catch (_) {}
  }

  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      const ip = (!err && address) ? address : '104.16.123.96';
      dnsCache.set(hostname, { ip, time: now });
      resolve(ip);
    });
  });
}

function checkHttpAuth(dataStr) {
  if (PROXY_AUTH_MODE === 'NONE' || proxyUsers.size === 0) return true;
  const match = dataStr.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
  if (!match) return false;
  try {
    const creds = Buffer.from(match[1], 'base64').toString('utf-8').split(':');
    return proxyUsers.has(creds[0]) && proxyUsers.get(creds[0]) === creds.slice(1).join(':');
  } catch (_) {
    return false;
  }
}

function parseTlsSni(buffer) {
  try {
    if (buffer[0] !== 0x16) return null;
    let pos = 43;
    if (pos >= buffer.length) return null;
    const sessionIdLen = buffer[pos];
    pos += 1 + sessionIdLen;
    const cipherSuitesLen = buffer.readUInt16BE(pos);
    pos += 2 + cipherSuitesLen;
    const compMethodsLen = buffer[pos];
    pos += 1 + compMethodsLen;
    if (pos >= buffer.length) return null;
    const extensionsLen = buffer.readUInt16BE(pos);
    pos += 2;
    const endExtensions = pos + extensionsLen;
    while (pos + 4 <= endExtensions && pos + 4 <= buffer.length) {
      const extType = buffer.readUInt16BE(pos);
      const extLen = buffer.readUInt16BE(pos + 2);
      pos += 4;
      if (extType === 0) {
        let sniPos = pos + 2;
        if (buffer[sniPos] === 0) {
          const nameLen = buffer.readUInt16BE(sniPos + 1);
          return buffer.toString('utf8', sniPos + 3, sniPos + 3 + nameLen);
        }
      }
      pos += extLen;
    }
  } catch (_) { return null; }
  return null;
}

function parseRequestBody(raw) {
  const delimiterIndex = raw.indexOf('\r\n\r\n');
  if (delimiterIndex === -1) return {};
  try { return JSON.parse(raw.slice(delimiterIndex + 4)); } catch (_) { return {}; }
}

// ==========================================
// 4. UDP RELAY ENGINE (HIGH-BUFFER OPTIMIZED)
// ==========================================
const RELAY_MAGIC = Buffer.from('VLRLY004', 'ascii');
const RELAY_MODE_FIXED_UDP = 0x01;
const RELAY_MODE_MUX = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6 = 0x03;
const MUX_STATUS_NEW = 0x01;
const MUX_STATUS_KEEP = 0x02;
const MUX_STATUS_END = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA = 0x01;
const MUX_OPTION_ERROR = 0x02;
const MUX_NETWORK_UDP = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_PACKET_LEN = 65535;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

function rejectUdpTarget(target) {
  return Boolean(UDP_CONFIG.REJECT_UDP_443 && Number(target?.port) === 443);
}

class AsyncByteReader {
  constructor(socket) {
    this.socket = socket;
    this.buffers = [];
    this.available = 0;
    this.waiters = [];
    this.ended = false;
    this.error = null;
    socket.on('data', (chunk) => {
      if (!chunk || chunk.length === 0) return;
      this.buffers.push(Buffer.from(chunk));
      this.available += chunk.length;
      this._flush();
    });
    socket.on('end', () => { this.ended = true; this._flush(); });
    socket.on('close', () => { this.ended = true; this._flush(); });
    socket.on('error', (err) => { this.error = err; this._flush(); });
  }
  readExactly(length) {
    if (!Number.isInteger(length) || length < 0) return Promise.reject(new Error('invalid read length'));
    if (length === 0) return Promise.resolve(Buffer.alloc(0));
    if (this.available >= length) return Promise.resolve(this._take(length));
    if (this.error) return Promise.reject(this.error);
    if (this.ended) return Promise.reject(new Error('unexpected EOF'));
    return new Promise((resolve, reject) => this.waiters.push({ length, resolve, reject }));
  }
  _flush() {
    while (this.waiters.length > 0) {
      const waiter = this.waiters[0];
      if (this.available >= waiter.length) {
        this.waiters.shift();
        waiter.resolve(this._take(waiter.length));
        continue;
      }
      if (this.error || this.ended) {
        this.waiters.shift();
        waiter.reject(this.error || new Error('unexpected EOF'));
        continue;
      }
      break;
    }
  }
  _take(length) {
    const out = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      const first = this.buffers[0];
      const need = length - offset;
      if (first.length <= need) {
        first.copy(out, offset);
        offset += first.length;
        this.buffers.shift();
      } else {
        first.copy(out, offset, 0, need);
        this.buffers[0] = first.subarray(need);
        offset += need;
      }
    }
    this.available -= length;
    return out;
  }
}

async function readLengthPayload(reader) {
  const lenBuf = await reader.readExactly(2);
  const length = lenBuf.readUInt16BE(0);
  return length === 0 ? Buffer.alloc(0) : reader.readExactly(length);
}

async function readEndpoint(reader) {
  const head = await reader.readExactly(3);
  const port = head.readUInt16BE(0);
  const atyp = head[2];
  if (port === 0) throw new Error('zero port');
  return readEndpointBody(reader, atyp, port);
}

async function readEndpointBody(reader, atyp, port) {
  if (atyp === ATYP_IPV4) {
    const b = await reader.readExactly(4);
    return { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp };
  }
  if (atyp === ATYP_DOMAIN) {
    const len = (await reader.readExactly(1))[0];
    if (len === 0) throw new Error('empty domain');
    const b = await reader.readExactly(len);
    let host;
    try { host = utf8Fatal.decode(b); } catch { throw new Error('invalid UTF-8 domain'); }
    if (!host) throw new Error('empty domain');
    return { host, port, atyp };
  }
  if (atyp === ATYP_IPV6) {
    const b = await reader.readExactly(16);
    return { host: formatIPv6(b), port, atyp };
  }
  throw new Error(`unknown address type ${atyp}`);
}

function parseEndpointBytes(buffer, offset) {
  if (offset < 0 || buffer.length - offset < 3) throw new Error('unexpected EOF in endpoint');
  const port = buffer.readUInt16BE(offset);
  if (port === 0) throw new Error('zero port');
  const atyp = buffer[offset + 2];
  let cursor = offset + 3;
  if (atyp === ATYP_IPV4) {
    if (buffer.length - cursor < 4) throw new Error('unexpected EOF in IPv4');
    const b = buffer.subarray(cursor, cursor + 4);
    return { endpoint: { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp }, next: cursor + 4 };
  }
  if (atyp === ATYP_DOMAIN) {
    if (buffer.length - cursor < 1) throw new Error('unexpected EOF in domain length');
    const len = buffer[cursor++];
    if (len === 0 || buffer.length - cursor < len) throw new Error('invalid domain length');
    let host;
    try { host = utf8Fatal.decode(buffer.subarray(cursor, cursor + len)); } catch { throw new Error('invalid UTF-8 domain'); }
    return { endpoint: { host, port, atyp }, next: cursor + len };
  }
  if (atyp === ATYP_IPV6) {
    if (buffer.length - cursor < 16) throw new Error('unexpected EOF in IPv6');
    const host = formatIPv6(buffer.subarray(cursor, cursor + 16));
    return { endpoint: { host, port, atyp }, next: cursor + 16 };
  }
  throw new Error(`unknown address type ${atyp}`);
}

function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
  return parts.join(':');
}

function ipv6ToBytes(address) {
  let input = address;
  const zone = input.indexOf('%');
  if (zone >= 0) input = input.slice(0, zone);
  let ipv4Tail = null;
  const lastColon = input.lastIndexOf(':');
  if (input.includes('.') && lastColon >= 0) {
    const ipv4 = input.slice(lastColon + 1).split('.').map(Number);
    if (ipv4.length !== 4 || ipv4.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) throw new Error(`invalid IPv6: ${address}`);
    ipv4Tail = [((ipv4[0] << 8) | ipv4[1]).toString(16), ((ipv4[2] << 8) | ipv4[3]).toString(16)];
    input = input.slice(0, lastColon) + ':' + ipv4Tail.join(':');
  }
  const halves = input.split('::');
  if (halves.length > 2) throw new Error(`invalid IPv6: ${address}`);
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) throw new Error(`invalid IPv6: ${address}`);
  const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  if (words.length !== 8) throw new Error(`invalid IPv6: ${address}`);
  const out = Buffer.alloc(16);
  words.forEach((word, i) => {
    if (!/^[0-9a-f]{1,4}$/i.test(word)) throw new Error(`invalid IPv6: ${address}`);
    out.writeUInt16BE(parseInt(word, 16), i * 2);
  });
  return out;
}

function encodeUDPSource(rinfo) {
  const port = Number(rinfo.port);
  const family = net.isIP(rinfo.address);
  const head = Buffer.alloc(3);
  head.writeUInt16BE(port, 0);
  if (family === 4) {
    head[2] = ATYP_IPV4;
    return Buffer.concat([head, Buffer.from(rinfo.address.split('.').map(Number))]);
  }
  if (family === 6) {
    head[2] = ATYP_IPV6;
    return Buffer.concat([head, ipv6ToBytes(rinfo.address)]);
  }
  throw new Error(`invalid UDP source IP: ${rinfo.address}`);
}

function writeSocket(socket, data) {
  if (socket.destroyed || !socket.writable) return Promise.reject(new Error('socket is closed'));
  return new Promise((resolve, reject) => socket.write(data, (err) => err ? reject(err) : resolve()));
}

async function writeControlError(socket, message) {
  let body = Buffer.from(String(message || 'relay error'), 'utf8');
  if (body.length > MAX_PACKET_LEN) body = body.subarray(0, MAX_PACKET_LEN);
  const out = Buffer.allocUnsafe(3 + body.length);
  out[0] = 1;
  out.writeUInt16BE(body.length, 1);
  body.copy(out, 3);
  try { await writeSocket(socket, out); } catch {}
}

async function readControl(reader) {
  const magic = await reader.readExactly(RELAY_MAGIC.length);
  if (!magic.equals(RELAY_MAGIC)) throw new Error('bad magic');
  const mode = (await reader.readExactly(1))[0];
  if (![RELAY_MODE_FIXED_UDP, RELAY_MODE_MUX, RELAY_MODE_PACKET_UDP].includes(mode)) throw new Error('bad mode');
  const target = mode === RELAY_MODE_FIXED_UDP ? await readEndpoint(reader) : null;
  return { mode, target };
}

async function resolveTargetUDP(target) {
  if (target.atyp === ATYP_IPV4) return { address: target.host, family: 4 };
  if (target.atyp === ATYP_IPV6) return { address: target.host, family: 6 };
  const records = await dnsPromises.lookup(target.host, { all: true, verbatim: true });
  if (!records.length) throw new Error(`DNS returned no address for ${target.host}`);
  const preferred = records.find((r) => r.family === 4) || records.find((r) => r.family === 6);
  if (!preferred) throw new Error(`DNS unsupported address for ${target.host}`);
  return preferred;
}

function bindDgram(socket, port, address) {
  return new Promise((resolve, reject) => {
    const onError = (err) => { cleanup(); reject(err); };
    const onListening = () => { cleanup(); resolve(); };
    const cleanup = () => {
      socket.off('error', onError);
      socket.off('listening', onListening);
    };
    socket.once('error', onError);
    socket.once('listening', onListening);
    socket.bind(port, address);
  });
}

class UDPAssociation {
  constructor() {
    this.udp4 = null;
    this.udp6 = null;
    this.port = 0;
    this.sink = null;
    this.closed = false;
  }
  static async create() {
    const assoc = new UDPAssociation();
    // Socket UDP dengan buffer 4MB untuk kecepatan transfer tinggi
    assoc.udp4 = dgram.createSocket({ 
      type: 'udp4', 
      reuseAddr: true,
      recvBufferSize: 4 * 1024 * 1024,
      sendBufferSize: 4 * 1024 * 1024
    });
    await bindDgram(assoc.udp4, 0, '0.0.0.0');
    assoc.port = assoc.udp4.address().port;
    assoc.udp4.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
    assoc.udp4.on('error', () => {});
    
    assoc.udp6 = dgram.createSocket({ 
      type: 'udp6', 
      reuseAddr: true, 
      ipv6Only: true,
      recvBufferSize: 4 * 1024 * 1024,
      sendBufferSize: 4 * 1024 * 1024
    });
    try {
      await bindDgram(assoc.udp6, assoc.port, '::');
      assoc.udp6.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
      assoc.udp6.on('error', () => {});
    } catch {
      try { assoc.udp6.close(); } catch {}
      assoc.udp6 = null;
    }
    return assoc;
  }
  attach(sink) {
    const old = this.sink;
    this.sink = sink;
    return old;
  }
  detach(mux, id) {
    if (this.sink && this.sink.mux === mux && this.sink.id === id) {
      this.sink = null;
      return true;
    }
    return false;
  }
  async send(target, payload) {
    if (this.closed) throw new Error('UDP association closed');
    if (payload.length > MAX_PACKET_LEN) throw new Error(`UDP payload too large: ${payload.length}`);
    const resolved = await resolveTargetUDP(target);
    const socket = resolved.family === 6 ? this.udp6 : this.udp4;
    if (!socket) throw new Error(`UDP IPv${resolved.family} unavailable`);
    await new Promise((resolve, reject) => {
      socket.send(payload, target.port, resolved.address, (err) => err ? reject(err) : resolve());
    });
    UDP_STATS.udpPacketsOut++;
    UDP_STATS.udpBytesOut += payload.length;
  }
  _onMessage(msg, rinfo) {
    UDP_STATS.udpPacketsIn++;
    UDP_STATS.udpBytesIn += msg.length;
    const sink = this.sink;
    if (!sink || this.closed) return;
    Promise.resolve(sink.mux.sendUDPData(sink.id, rinfo, Buffer.from(msg))).catch(() => {});
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.sink = null;
    if (this.udp4) { try { this.udp4.close(); } catch {} }
    if (this.udp6) { try { this.udp6.close(); } catch {} }
    this.udp4 = null;
    this.udp6 = null;
  }
}

class XUDPManager {
  constructor(graceMs) {
    this.graceMs = graceMs;
    this.entries = new Map();
  }
  async attach(globalID, mux, sessionID) {
    const key = Buffer.from(globalID).toString('hex');
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { assoc: await UDPAssociation.create(), timer: null };
      this.entries.set(key, entry);
    }
    if (entry.timer) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    const oldSink = entry.assoc.attach({ mux, id: sessionID });
    return { assoc: entry.assoc, oldSink };
  }
  detach(globalID, mux, sessionID) {
    const key = Buffer.from(globalID).toString('hex');
    const entry = this.entries.get(key);
    if (!entry || !entry.assoc.detach(mux, sessionID)) return;
    if (entry.timer) clearTimeout(entry.timer);
    entry.timer = setTimeout(() => {
      const current = this.entries.get(key);
      if (current !== entry) return;
      this.entries.delete(key);
      entry.assoc.close();
    }, this.graceMs);
    entry.timer.unref?.();
  }
  close() {
    for (const entry of this.entries.values()) {
      if (entry.timer) clearTimeout(entry.timer);
      entry.assoc.close();
    }
    this.entries.clear();
  }
}

async function serveDirectUDP(socket, reader, target) {
  if (rejectUdpTarget(target)) {
    await writeControlError(socket, 'UDP/443 rejected');
    return;
  }
  const assoc = await UDPAssociation.create();
  let closed = false;
  assoc.attach({
    mux: {
      sendUDPData: async (_id, _rinfo, data) => {
        if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return;
        const frame = Buffer.allocUnsafe(2 + data.length);
        frame.writeUInt16BE(data.length, 0);
        data.copy(frame, 2);
        await writeSocket(socket, frame);
      },
    },
    id: 0,
  });
  try {
    await writeSocket(socket, Buffer.from([0]));
    for (;;) {
      const payload = await readLengthPayload(reader);
      if (payload.length === 0 || rejectUdpTarget(target)) continue;
      await assoc.send(target, payload);
    }
  } finally {
    closed = true;
    assoc.close();
  }
}

async function servePacketUDP(socket, reader) {
  const assoc = await UDPAssociation.create();
  let closed = false;
  const writeChain = { value: Promise.resolve() };
  assoc.attach({
    mux: {
      sendUDPData: (_id, rinfo, data) => {
        if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return Promise.resolve();
        const endpoint = encodeUDPSource(rinfo);
        const len = Buffer.allocUnsafe(2);
        len.writeUInt16BE(data.length, 0);
        const frame = Buffer.concat([endpoint, len, data]);
        const op = writeChain.value.then(() => writeSocket(socket, frame));
        writeChain.value = op.catch(() => {});
        return op;
      },
    },
    id: 0,
  });
  try {
    await writeSocket(socket, Buffer.from([0]));
    for (;;) {
      const target = await readEndpoint(reader);
      const payload = await readLengthPayload(reader);
      if (payload.length === 0 || rejectUdpTarget(target)) continue;
      await assoc.send(target, payload);
    }
  } finally {
    closed = true;
    assoc.close();
  }
}

async function readMuxFrame(reader) {
  const metaLen = (await reader.readExactly(2)).readUInt16BE(0);
  if (metaLen < 4 || metaLen > MAX_MUX_META_LEN) throw new Error(`invalid mux length ${metaLen}`);
  const meta = await reader.readExactly(metaLen);
  const frame = {
    id: meta.readUInt16BE(0),
    status: meta[2],
    option: meta[3],
    network: 0,
    target: null,
    globalID: null,
    data: Buffer.alloc(0),
  };
  let cursor = 4;
  if (frame.status === MUX_STATUS_NEW) {
    if (cursor >= meta.length) throw new Error('mux New missing network');
    frame.network = meta[cursor++];
    const parsed = parseEndpointBytes(meta, cursor);
    frame.target = parsed.endpoint;
    cursor = parsed.next;
    if (frame.network === MUX_NETWORK_UDP && meta.length - cursor >= 8) {
      const gid = meta.subarray(cursor, cursor + 8);
      if (!gid.equals(Buffer.alloc(8))) frame.globalID = Buffer.from(gid);
      cursor += 8;
    }
    if (cursor !== meta.length) throw new Error(`unexpected bytes in mux New metadata`);
  } else if (frame.status === MUX_STATUS_KEEP && meta.length > cursor && meta[cursor] === MUX_NETWORK_UDP) {
    frame.network = meta[cursor++];
    frame.target = parseEndpointBytes(meta, cursor).endpoint;
  }
  if ((frame.option & MUX_OPTION_DATA) !== 0) frame.data = await readLengthPayload(reader);
  return frame;
}

class MuxSession {
  constructor(mux, id, network, target) {
    this.mux = mux;
    this.id = id;
    this.network = network;
    this.target = target;
    this.udp = null;
    this.global = false;
    this.gid = null;
    this.closed = false;
  }
  async sendUDP(target, payload) {
    if (!this.udp) throw new Error('UDP session unavailable');
    await this.udp.send(target, payload);
  }
  closeWithoutRemoving() {
    if (this.closed) return;
    this.closed = true;
    if (this.udp) {
      if (this.global) this.mux.xm.detach(this.gid, this.mux, this.id);
      else { this.udp.detach(this.mux, this.id); this.udp.close(); }
      this.udp = null;
    }
  }
  async close(sendEnd) {
    if (this.mux.sessions.get(this.id) === this) this.mux.sessions.delete(this.id);
    this.closeWithoutRemoving();
    if (sendEnd) await this.mux.sendEnd(this.id, true).catch(() => {});
  }
}

class MuxConnection {
  constructor(socket, reader, cfg, xm) {
    this.socket = socket;
    this.reader = reader;
    this.cfg = cfg;
    this.xm = xm;
    this.sessions = new Map();
    this.closed = false;
    this.writeChain = Promise.resolve();
  }
  async serve() {
    try {
      await writeSocket(this.socket, Buffer.from([0]));
      for (;;) {
        const frame = await readMuxFrame(this.reader);
        await this.handleFrame(frame);
      }
    } finally {
      this.closeAll();
    }
  }
  async handleFrame(frame) {
    if (frame.status === MUX_STATUS_KEEPALIVE) return;
    if (frame.status === MUX_STATUS_NEW) return this.handleNew(frame);
    if (frame.status === MUX_STATUS_KEEP) return this.handleKeep(frame);
    if (frame.status === MUX_STATUS_END) {
      const session = this.sessions.get(frame.id);
      if (session && frame.data.length) await session.sendUDP(session.target, frame.data).catch(() => {});
      this.removeSession(frame.id);
      return;
    }
    throw new Error(`unknown mux status 0x${frame.status.toString(16).padStart(2, '0')}`);
  }
  async handleNew(frame) {
    if (frame.network !== MUX_NETWORK_UDP || !frame.target?.host || !frame.target?.port || rejectUdpTarget(frame.target)) {
      await this.sendEnd(frame.id, true).catch(() => {});
      return;
    }
    this.removeSession(frame.id);
    const session = new MuxSession(this, frame.id, frame.network, frame.target);
    if (frame.globalID) {
      try {
        const { assoc, oldSink } = await this.xm.attach(frame.globalID, this, frame.id);
        session.udp = assoc;
        session.global = true;
        session.gid = Buffer.from(frame.globalID);
        this.sessions.set(session.id, session);
        if (oldSink && (oldSink.mux !== this || oldSink.id !== frame.id)) {
          oldSink.mux.removeSession(oldSink.id);
          await oldSink.mux.sendEnd(oldSink.id, false).catch(() => {});
        }
      } catch {
        await this.sendEnd(frame.id, true).catch(() => {});
        return;
      }
    } else {
      try {
        const assoc = await UDPAssociation.create();
        assoc.attach({ mux: this, id: frame.id });
        session.udp = assoc;
        this.sessions.set(session.id, session);
      } catch {
        await this.sendEnd(frame.id, true).catch(() => {});
        return;
      }
    }
    if (frame.data.length) await session.sendUDP(frame.target, frame.data).catch(() => session.close(true));
  }
  async handleKeep(frame) {
    const session = this.sessions.get(frame.id);
    if (!session) {
      await this.sendEnd(frame.id, false).catch(() => {});
      return;
    }
    if (!frame.data.length) return;
    let target = session.target;
    if (frame.network === MUX_NETWORK_UDP && frame.target?.host && frame.target?.port) {
      target = frame.target;
      session.target = target;
    }
    if (rejectUdpTarget(target)) {
      await session.close(true);
      return;
    }
    await session.sendUDP(target, frame.data).catch(() => session.close(true));
  }
  removeSession(id) {
    const session = this.sessions.get(id);
    if (!session) return;
    this.sessions.delete(id);
    session.closeWithoutRemoving();
  }
  closeAll() {
    if (this.closed) return;
    this.closed = true;
    const sessions = [...this.sessions.values()];
    this.sessions.clear();
    for (const s of sessions) s.closeWithoutRemoving();
  }
  _queueWrite(data) {
    const op = this.writeChain.then(() => writeSocket(this.socket, data));
    this.writeChain = op.catch(() => {});
    return op;
  }
  sendUDPData(id, source, data) {
    const addr = encodeUDPSource(source);
    const meta = Buffer.allocUnsafe(5 + addr.length);
    meta.writeUInt16BE(id, 0);
    meta[2] = MUX_STATUS_KEEP;
    meta[3] = MUX_OPTION_DATA;
    meta[4] = MUX_NETWORK_UDP;
    addr.copy(meta, 5);
    return this.writeMuxPacket(meta, data);
  }
  sendEnd(id, hasError) {
    const meta = Buffer.alloc(4);
    meta.writeUInt16BE(id, 0);
    meta[2] = MUX_STATUS_END;
    meta[3] = hasError ? MUX_OPTION_ERROR : 0;
    return this.writeMuxMeta(meta);
  }
  writeMuxPacket(meta, data) {
    if (data.length > MAX_PACKET_LEN) return Promise.reject(new Error(`mux payload too large: ${data.length}`));
    const out = Buffer.allocUnsafe(2 + meta.length + 2 + data.length);
    out.writeUInt16BE(meta.length, 0);
    meta.copy(out, 2);
    const off = 2 + meta.length;
    out.writeUInt16BE(data.length, off);
    data.copy(out, off + 2);
    return this._queueWrite(out);
  }
  writeMuxMeta(meta) {
    const out = Buffer.allocUnsafe(2 + meta.length);
    out.writeUInt16BE(meta.length, 0);
    meta.copy(out, 2);
    return this._queueWrite(out);
  }
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function websocketAccept(key) {
  return createHash('sha1').update(String(key) + WS_GUID, 'ascii').digest('base64');
}

function websocketFrame(opcode, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let header;
  if (body.length < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = body.length;
  } else if (body.length <= 0xffff) {
    header = Buffer.allocUnsafe(4);
    header[1] = 126;
    header.writeUInt16BE(body.length, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(body.length), 2);
  }
  header[0] = 0x80 | (opcode & 0x0f);
  return body.length ? Buffer.concat([header, body]) : header;
}

function websocketClosePayload(code, reason = '') {
  let text = Buffer.from(String(reason), 'utf8');
  if (text.length > 123) text = text.subarray(0, 123);
  const out = Buffer.allocUnsafe(2 + text.length);
  out.writeUInt16BE(code, 0);
  text.copy(out, 2);
  return out;
}

class WebSocketRelaySocket extends EventEmitter {
  constructor(raw, maxMessageBytes) {
    super();
    this.raw = raw;
    this.remoteAddress = raw.remoteAddress;
    this.remotePort = raw.remotePort;
    this.destroyed = false;
    this.writable = true;
    this.buffer = Buffer.alloc(0);
    this.fragmentOpcode = 0;
    this.fragmentParts = [];
    this.fragmentBytes = 0;
    this.maxMessageBytes = maxMessageBytes;
    this.timeoutMs = 0;
    this.timeoutCallback = null;
    this.timeoutTimer = null;
    this.sentClose = false;
    this.gotClose = false;
    this.ended = false;
    raw.on('data', (chunk) => {
      if (this.destroyed || !chunk?.length) return;
      this._touch();
      this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : Buffer.from(chunk);
      this._parse();
    });
    raw.on('end', () => this._emitEnd());
    raw.on('close', () => {
      if (this.destroyed) return;
      this.destroyed = true;
      this.writable = false;
      this._clearTimeout();
      this._emitEnd();
      this.emit('close');
    });
    raw.on('error', (err) => {
      if (this.listenerCount('error')) this.emit('error', err);
    });
  }
  feedHead(head) {
    if (!head?.length || this.destroyed) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, head]) : Buffer.from(head);
    this._parse();
  }
  setNoDelay(value = true) {
    this.raw.setNoDelay(value);
    return this;
  }
  setTimeout(ms, callback) {
    this.timeoutMs = Number(ms) || 0;
    this.timeoutCallback = typeof callback === 'function' ? callback : null;
    this._touch();
    return this;
  }
  _clearTimeout() {
    if (this.timeoutTimer) clearTimeout(this.timeoutTimer);
    this.timeoutTimer = null;
  }
  _touch() {
    this._clearTimeout();
    if (this.timeoutMs > 0 && !this.destroyed) {
      this.timeoutTimer = setTimeout(() => {
        this.timeoutTimer = null;
        if (this.timeoutCallback && !this.destroyed) this.timeoutCallback();
      }, this.timeoutMs);
      this.timeoutTimer.unref?.();
    }
  }
  write(data, callback) {
    if (this.destroyed || !this.writable) {
      const err = new Error('socket is closed');
      err.code = 'EPIPE';
      if (callback) queueMicrotask(() => callback(err));
      return false;
    }
    const frame = websocketFrame(0x2, Buffer.from(data));
    this._touch();
    return this.raw.write(frame, callback);
  }
  _writeControl(opcode, payload = Buffer.alloc(0)) {
    if (this.destroyed || !this.writable) return;
    this._touch();
    this.raw.write(websocketFrame(opcode, payload));
  }
  _protocolError(reason) {
    if (!this.sentClose) {
      this.sentClose = true;
      this._writeControl(0x8, websocketClosePayload(1002, reason));
    }
    const err = new Error(`WebSocket protocol error: ${reason}`);
    err.code = 'EPROTO';
    if (this.listenerCount('error')) this.emit('error', err);
    this.destroy(err);
  }
  _messageTooLarge() {
    if (!this.sentClose) {
      this.sentClose = true;
      this._writeControl(0x8, websocketClosePayload(1009, 'message too large'));
    }
    this.destroy(new Error('WebSocket message too large'));
  }
  _parse() {
    try {
      while (!this.destroyed) {
        if (this.buffer.length < 2) return;
        const b0 = this.buffer[0];
        const b1 = this.buffer[1];
        const fin = Boolean(b0 & 0x80);
        const rsv = b0 & 0x70;
        const opcode = b0 & 0x0f;
        const masked = Boolean(b1 & 0x80);
        let length = b1 & 0x7f;
        let offset = 2;
        if (rsv) return this._protocolError('RSV bits not supported');
        if (!masked) return this._protocolError('must be masked');
        if (length === 126) {
          if (this.buffer.length < 4) return;
          length = this.buffer.readUInt16BE(2);
          offset = 4;
        } else if (length === 127) {
          if (this.buffer.length < 10) return;
          const n = this.buffer.readBigUInt64BE(2);
          if (n > BigInt(Number.MAX_SAFE_INTEGER)) return this._messageTooLarge();
          length = Number(n);
          offset = 10;
        }
        if (opcode >= 0x8 && (!fin || length > 125)) return this._protocolError('invalid control');
        if (length > this.maxMessageBytes) return this._messageTooLarge();
        if (this.buffer.length < offset + 4 + length) return;
        const mask = this.buffer.subarray(offset, offset + 4);
        offset += 4;
        const payload = Buffer.from(this.buffer.subarray(offset, offset + length));
        this.buffer = this.buffer.subarray(offset + length);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
        if (opcode === 0x8) {
          this.gotClose = true;
          if (!this.sentClose) {
            this.sentClose = true;
            this._writeControl(0x8, payload);
          }
          this._emitEnd();
          this.writable = false;
          this.raw.end();
          return;
        }
        if (opcode === 0x9) { this._writeControl(0xA, payload); continue; }
        if (opcode === 0xA) continue;
        if (opcode === 0x1) {
          if (!this.sentClose) {
            this.sentClose = true;
            this._writeControl(0x8, websocketClosePayload(1003, 'binary only'));
          }
          this.raw.end();
          return;
        }
        if (opcode === 0x2) {
          if (this.fragmentOpcode) return this._protocolError('fragment error');
          if (fin) this._emitBinary(payload);
          else {
            this.fragmentOpcode = opcode;
            this.fragmentParts = [payload];
            this.fragmentBytes = payload.length;
          }
          continue;
        }
        if (opcode === 0x0) {
          if (!this.fragmentOpcode) return this._protocolError('unexpected continuation');
          this.fragmentBytes += payload.length;
          if (this.fragmentBytes > this.maxMessageBytes) return this._messageTooLarge();
          this.fragmentParts.push(payload);
          if (fin) {
            const joined = Buffer.concat(this.fragmentParts, this.fragmentBytes);
            this.fragmentOpcode = 0;
            this.fragmentParts = [];
            this.fragmentBytes = 0;
            this._emitBinary(joined);
          }
          continue;
        }
        return this._protocolError(`unsupported opcode ${opcode}`);
      }
    } catch (err) {
      if (this.listenerCount('error')) this.emit('error', err);
      this.destroy(err);
    }
  }
  _emitBinary(payload) { if (payload.length) this.emit('data', payload); }
  _emitEnd() { if (this.ended) return; this.ended = true; this.emit('end'); }
  destroy(error) {
    if (this.destroyed) return;
    this.destroyed = true;
    this.writable = false;
    this._clearTimeout();
    if (error && this.listenerCount('error')) this.emit('error', error);
    this.raw.destroy();
    this._emitEnd();
    this.emit('close');
  }
}

const xm = new XUDPManager(UDP_CONFIG.XUDP_GRACE_MS);

async function handleConnectionUDP(socket, cfg) {
  const reader = new AsyncByteReader(socket);
  let established = false;
  socket.setNoDelay(true);
  socket.setTimeout(cfg.HANDSHAKE_TIMEOUT_MS, () => socket.destroy(new Error('handshake timeout')));
  try {
    const control = await readControl(reader);
    established = true;
    addUdpLog(`[OK] Handshake Valid | Mode: 0x${control.mode.toString(16)} | IP: ${socket.remoteAddress || 'Worker'}`);
    socket.setTimeout(cfg.IDLE_TIMEOUT_MS > 0 ? cfg.IDLE_TIMEOUT_MS : 0, () => socket.destroy(new Error('idle timeout')));
    if (control.mode === RELAY_MODE_FIXED_UDP) await serveDirectUDP(socket, reader, control.target);
    else if (control.mode === RELAY_MODE_PACKET_UDP) await servePacketUDP(socket, reader);
    else {
      const mux = new MuxConnection(socket, reader, cfg, xm);
      await mux.serve();
    }
  } catch (err) {
    if (!established && !socket.destroyed) {
      addUdpLog(`[WARN] Handshake UDP Gagal`);
      await writeControlError(socket, 'malformed header');
    }
  } finally {
    socket.destroy();
  }
}

// ==========================================
// 5. DASHBOARD UI BUILDER
// ==========================================
function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Dual Service Hub (UDP Relay & Proxy)</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #06090e; color: #00ffcc; padding: 14px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0c121e; border: 1px solid #00ffcc; box-shadow: 0 0 20px rgba(0,255,204,0.15); border-radius: 14px; max-width: 620px; width: 100%; padding: 18px; }
    h2 { margin: 0 0 16px 0; color: #38bdf8; text-align: center; font-size: 1.2rem; }
    .endpoint-box { background: #030712; border: 1px solid #38bdf8; border-radius: 10px; padding: 10px 12px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
    .endpoint-title { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .endpoint-val { font-family: monospace; font-size: 0.95rem; font-weight: bold; color: #39ff14; word-break: break-all; }
    .btn-copy { background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 6px 10px; border-radius: 6px; font-size: 0.72rem; font-weight: bold; cursor: pointer; white-space: nowrap; margin-left: 8px; }
    .badge-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 16px; }
    .badge { background: #030712; border: 1px solid #1e293b; border-radius: 10px; padding: 10px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.70rem; color: #94a3b8; text-transform: uppercase; }
    .badge .val { font-size: 1.15rem; font-weight: bold; margin-top: 4px; font-family: monospace; }
    .badge .sub-val { font-size: 0.65rem; color: #94a3b8; margin-top: 2px; font-family: monospace; }
    .section-title { font-size: 0.85rem; font-weight: bold; color: #38bdf8; margin-top: 14px; margin-bottom: 8px; }
    .panel { background: #070d17; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-top: 12px; }
    .hint { font-size: 0.70rem; color: #94a3b8; margin-top: 4px; }
    select, input { width: 100%; padding: 8px; background: #030712; border: 1px solid #1e293b; border-radius: 6px; color: #fff; margin-top: 5px; font-family: monospace; font-size: 0.80rem; }
    button { width: 100%; padding: 9px; background: #00ffcc; color: #000; font-weight: bold; border: none; border-radius: 6px; margin-top: 8px; cursor: pointer; }
    .log-box { font-family: monospace; font-size: 0.72rem; background: #030712; padding: 8px; border-radius: 6px; height: 130px; overflow-y: auto; color: #a5f3fc; border: 1px solid #1e293b; }
    .conn-list { display: flex; flex-direction: column; gap: 6px; max-height: 150px; overflow-y: auto; }
    .conn-item { background: #030712; border: 1px solid #1e293b; border-left: 3px solid #39ff14; border-radius: 6px; padding: 6px 8px; font-size: 0.75rem; }
    .tag { background: #032b17; color: #39ff14; padding: 2px 5px; border-radius: 4px; font-size: 0.65rem; }
    .user-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    .user-table td { padding: 6px 4px; border-bottom: 1px solid #1e293b; font-size: 0.8rem; font-family: monospace; }
    .btn-del { background: #ef4444; color: #fff; padding: 4px 8px; border-radius: 4px; border: none; cursor: pointer; font-size: 0.7rem; width: auto; margin-top: 0; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚡ DUAL SERVICE CONTROLLER</h2>

    <div class="endpoint-box" style="border-color:#38bdf8;">
      <div>
        <div class="endpoint-title">🚀 UDP Relay WSS Endpoint (Port 443)</div>
        <div class="endpoint-val" id="udp_url">${UDP_ENDPOINT_URL}</div>
      </div>
      <button class="btn-copy" onclick="navigator.clipboard.writeText(document.getElementById('udp_url').innerText)">📋 SALIN</button>
    </div>

    <div class="endpoint-box" style="border-color:#a855f7;">
      <div>
        <div class="endpoint-title" style="color:#c084fc;">🛠️ Multi-Proxy Endpoint (TCP Port)</div>
        <div class="endpoint-val" style="color:#c084fc;" id="proxy_tcp_url">${PROXY_SERVER_INFO.fullProxy || 'Loading...'}</div>
      </div>
      <button class="btn-copy" style="border-color:#c084fc; color:#c084fc;" onclick="navigator.clipboard.writeText(document.getElementById('proxy_tcp_url').innerText)">📋 SALIN</button>
    </div>

    <div class="badge-grid">
      <div class="badge" style="border-color:#38bdf8;">
        <h4>UDP In / Recv</h4>
        <div class="val" style="color:#38bdf8;" id="udp_bytes_in">0 B</div>
        <div class="sub-val" id="udp_pkt_in">0 pkt</div>
      </div>
      <div class="badge" style="border-color:#38bdf8;">
        <h4>UDP Out / Sent</h4>
        <div class="val" style="color:#38bdf8;" id="udp_bytes_out">0 B</div>
        <div class="sub-val" id="udp_pkt_out">0 pkt</div>
      </div>
      <div class="badge" style="border-color:#00ffcc;">
        <h4>Proxy RX (In)</h4>
        <div class="val" style="color:#00ffcc;" id="proxy_bytes_in">0 B</div>
        <div class="sub-val">HTTP/SOCKS/RAW</div>
      </div>
      <div class="badge" style="border-color:#f59e0b;">
        <h4>Proxy TX (Out)</h4>
        <div class="val" style="color:#f59e0b;" id="proxy_bytes_out">0 B</div>
        <div class="sub-val">HTTP/SOCKS/RAW</div>
      </div>
    </div>

    <div class="badge-grid" style="margin-bottom:8px;">
      <div class="badge">
        <h4>Klien Aktif (UDP / Proxy)</h4>
        <div class="val" style="color:#39ff14;" id="combined_active">0 / 0</div>
      </div>
      <div class="badge">
        <h4>DNS Resolver Status</h4>
        <div class="val" style="color:#38bdf8; font-size:0.95rem;" id="badge_dns_mode">${DNS_CONFIG.mode}</div>
      </div>
    </div>

    <div class="panel" style="border-color:#38bdf8;">
      <div class="section-title" style="margin:0; color:#38bdf8;">📡 REAL-TIME UDP RELAY LOGS</div>
      <div class="log-box" id="udp_log_box" style="margin-top:6px;">Menunggu aktivitas paket UDP...</div>
    </div>

    <div class="panel" style="border-color:#38bdf8;">
      <div class="section-title" style="margin:0; color:#38bdf8;">🌐 PENGATURAN DNS RESOLVER</div>
      <select id="preset_select" onchange="applyPresetUI()">
        <option value="cf-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '1.1.1.1' ? 'selected' : ''}>🚀 Cloudflare UDP 1.1.1.1:53 (Paling Cepat)</option>
        <option value="google-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '8.8.8.8' ? 'selected' : ''}>🚀 Google UDP 8.8.8.8:53 (Bagus YouTube)</option>
        <option value="cf-doh" ${DNS_CONFIG.mode === 'DOH' && DNS_CONFIG.dohUrl.includes('cloudflare') ? 'selected' : ''}>⚡ Cloudflare DoH (Official)</option>
        <option value="google-doh" ${DNS_CONFIG.mode === 'DOH' && DNS_CONFIG.dohUrl.includes('google') ? 'selected' : ''}>⚡ Google DoH (Official)</option>
        <option value="quad9-udp" ${DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer === '9.9.9.9' ? 'selected' : ''}>🛡️ Quad9 UDP 9.9.9.9:53</option>
        <option value="quad9-doh">🛡️ Quad9 DoH (Security)</option>
        <option value="adguard-doh">🛑 AdGuard DoH (Adblock)</option>
        <option value="custom_doh">✏️ Custom DoH URL</option>
        <option value="custom_udp">✏️ Custom UDP IP/Port</option>
      </select>
      <div id="box_custom_doh" style="display:none; margin-top:6px;">
        <input type="text" id="custom_doh_url" placeholder="https://dns.nextdns.io/xxxxxx" value="${DNS_CONFIG.dohUrl}">
      </div>
      <div id="box_custom_udp" style="display:none; margin-top:6px;">
        <input type="text" id="custom_udp_ip" placeholder="1.1.1.1" value="${DNS_CONFIG.udpServer}">
        <input type="number" id="custom_udp_port" placeholder="53" value="${DNS_CONFIG.udpPort || 53}">
      </div>
      <button style="background:#38bdf8;" onclick="saveDns()">💾 TERAPKAN DNS</button>
    </div>

    <div class="panel" style="border-color:#a855f7;">
      <div class="section-title" style="margin:0; color:#c084fc;">🛠️ KONTROL PROXY RAW TCP</div>
      <select id="raw_tcp_switch">
        <option value="true" ${RAW_TCP_CONFIG.enabled ? 'selected' : ''}>🟢 AKTIF (Terima Paket Mentah)</option>
        <option value="false" ${!RAW_TCP_CONFIG.enabled ? 'selected' : ''}>🔴 NONAKTIF</option>
      </select>
      <input type="text" id="raw_tcp_host" placeholder="Target Host" value="${RAW_TCP_CONFIG.defaultTargetHost}">
      <input type="number" id="raw_tcp_port" placeholder="Target Port" value="${RAW_TCP_CONFIG.defaultTargetPort}">
      <button style="background:#a855f7; color:#fff;" onclick="saveRawTcp()">💾 SIMPAN PENGATURAN RAW TCP</button>
    </div>

    <div class="panel">
      <div class="section-title" style="margin:0;">👤 USER & PASSWORD PROXY</div>
      <div style="margin-top:8px;">
        <select id="select_auth_mode" onchange="changeAuthMode()">
          <option value="NONE" ${PROXY_AUTH_MODE === 'NONE' ? 'selected' : ''}>Tanpa Auth (Public Proxy)</option>
          <option value="AUTH" ${PROXY_AUTH_MODE === 'AUTH' ? 'selected' : ''}>Wajib User & Pass (Private Proxy)</option>
        </select>
      </div>
      <table class="user-table">
        <tbody id="user_list_body"></tbody>
      </table>
      <div style="display:flex; gap:6px; margin-top:10px;">
        <input type="text" id="new_proxy_user" placeholder="User Baru">
        <input type="text" id="new_proxy_pass" placeholder="Pass Baru">
      </div>
      <button onclick="addUser()">+ TAMBAH USER PROXY</button>
    </div>

    <div class="section-title">🟢 LIVE CONNECTIONS (REAL-TIME)</div>
    <div class="conn-list" id="proxy_conn_container"></div>
  </div>

  <script>
    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('udp_bytes_in').innerText = data.udp.bytesInDisplay;
        document.getElementById('udp_bytes_out').innerText = data.udp.bytesOutDisplay;
        document.getElementById('udp_pkt_in').innerText = data.udp.packetsIn + ' pkt';
        document.getElementById('udp_pkt_out').innerText = data.udp.packetsOut + ' pkt';

        document.getElementById('proxy_bytes_in').innerText = data.proxy.bytesInDisplay;
        document.getElementById('proxy_bytes_out').innerText = data.proxy.bytesOutDisplay;

        document.getElementById('combined_active').innerText = data.udp.activeClients + ' / ' + data.proxy.totalActive;
        if (data.proxy.info && data.proxy.info.fullProxy) {
          document.getElementById('proxy_tcp_url').innerText = data.proxy.info.fullProxy;
        }

        renderUsers(data.proxy.userList);

        const logBox = document.getElementById('udp_log_box');
        if (data.udp.recentLogs && data.udp.recentLogs.length > 0) {
          logBox.innerHTML = data.udp.recentLogs.map(l => '<div>' + l + '</div>').join('');
        }

        const connContainer = document.getElementById('proxy_conn_container');
        if (!data.proxy.connections || data.proxy.connections.length === 0) {
          connContainer.innerHTML = '<div style="text-align:center;color:#64748b;font-size:0.75rem;padding:6px;">Belum ada perangkat terhubung ke proxy...</div>';
        } else {
          connContainer.innerHTML = data.proxy.connections.map(c => \`
            <div class="conn-item">
              <div style="display:flex; justify-content:space-between;">
                <b>\${c.clientIp}</b>
                <span class="tag">\${c.type}</span>
              </div>
              <div style="color:#38bdf8; font-family:monospace; margin:2px 0;">🎯 \${c.target}</div>
              <div style="color:#94a3b8; font-size:0.68rem;">RX: \${c.bytesIn} | TX: \${c.bytesOut} | ⏱️ \${c.uptime}s</div>
            </div>
          \`).join('');
        }
      } catch (e) {}
    }

    function renderUsers(users) {
      const tbody = document.getElementById('user_list_body');
      if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="color:#64748b; text-align:center;">Belum ada user proxy ditambahkan.</td></tr>';
        return;
      }
      tbody.innerHTML = users.map(u => \`
        <tr>
          <td>👤 <b>\${u.username}</b></td>
          <td style="color:#94a3b8;">🔑 \${u.password}</td>
          <td style="text-align:right;"><button class="btn-del" onclick="deleteUser('\${u.username}')">Hapus</button></td>
        </tr>
      \`).join('');
    }

    function applyPresetUI() {
      const val = document.getElementById('preset_select').value;
      document.getElementById('box_custom_doh').style.display = (val === 'custom_doh') ? 'block' : 'none';
      document.getElementById('box_custom_udp').style.display = (val === 'custom_udp') ? 'block' : 'none';
    }

    async function saveDns() {
      const selected = document.getElementById('preset_select').value;
      let payload = {};
      if (selected === 'custom_doh') {
        payload = { mode: 'DOH', dohUrl: document.getElementById('custom_doh_url').value.trim() };
      } else if (selected === 'custom_udp') {
        payload = {
          mode: 'UDP',
          udpServer: document.getElementById('custom_udp_ip').value.trim(),
          udpPort: document.getElementById('custom_udp_port').value.trim()
        };
      } else {
        payload = { preset: selected };
      }

      await fetch('/api/set-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      fetchStats();
    }

    async function saveRawTcp() {
      const enabled = document.getElementById('raw_tcp_switch').value === 'true';
      const host = document.getElementById('raw_tcp_host').value.trim();
      const port = document.getElementById('raw_tcp_port').value.trim();
      await fetch('/api/set-raw-tcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, defaultTargetHost: host, defaultTargetPort: port })
      });
      fetchStats();
    }

    async function addUser() {
      const u = document.getElementById('new_proxy_user').value.trim();
      const p = document.getElementById('new_proxy_pass').value.trim();
      if (!u || !p) return alert('Isi user & password!');
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', username: u, password: p })
      });
      document.getElementById('new_proxy_user').value = '';
      document.getElementById('new_proxy_pass').value = '';
      fetchStats();
    }

    async function deleteUser(u) {
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', username: u })
      });
      fetchStats();
    }

    async function changeAuthMode() {
      const mode = document.getElementById('select_auth_mode').value;
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'set-mode', mode })
      });
      fetchStats();
    }

    setInterval(fetchStats, 1500);
    fetchStats();
  </script>
</body>
</html>`;
}

// ==========================================
// 6. CORE MULTIPLEXER (HIGH-SPEED SOCKET ENGINE)
// ==========================================
function setupConnectionHandler(clientSocket) {
  // Matikan Nagle Algorithm dan optimasi buffer
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);
  clientSocket.setMaxListeners(0);

  const connId = ++connectionIdCounter;
  const rawIp = clientSocket.remoteAddress || 'Unknown';
  const clientIp = rawIp.replace('::ffff:', '');
  const startTime = Date.now();

  const connData = {
    id: connId,
    clientIp,
    type: 'INITIALIZING',
    target: 'pending',
    startTime,
    bytesIn: 0,
    bytesOut: 0
  };

  let isFirstPacket = true;
  let targetSocket = null;
  let socksState = 0;
  let httpBuffer = '';

  const bridgeSockets = (sockA, sockB) => {
    if (sockA.setNoDelay) sockA.setNoDelay(true);
    if (sockB.setNoDelay) sockB.setNoDelay(true);

    sockA.pipe(sockB, { end: true });
    sockB.pipe(sockA, { end: true });

    sockA.on('data', (d) => {
      connData.bytesIn += d.length;
      proxyBytesIn += d.length;
    });
    sockB.on('data', (d) => {
      connData.bytesOut += d.length;
      proxyBytesOut += d.length;
    });

    const cleanup = () => {
      activeConnections.delete(connId);
      sockA.destroy();
      sockB.destroy();
    };

    sockA.on('error', cleanup);
    sockB.on('error', cleanup);
    sockA.on('close', cleanup);
    sockB.on('close', cleanup);
  };

  const handleSocks5 = async (chunk) => {
    if (socksState === 0) {
      const nmethods = chunk[1];
      const methods = chunk.slice(2, 2 + nmethods);
      const requiresAuth = (PROXY_AUTH_MODE === 'AUTH' && proxyUsers.size > 0);

      if (requiresAuth) {
        if (!methods.includes(0x02)) {
          clientSocket.write(Buffer.from([0x05, 0xFF]));
          return clientSocket.end();
        }
        socksState = 1;
        clientSocket.write(Buffer.from([0x05, 0x02]));
      } else {
        socksState = 2;
        clientSocket.write(Buffer.from([0x05, 0x00]));
      }
      return;
    }

    if (socksState === 1) {
      if (chunk[0] !== 0x01) return clientSocket.end();
      const uLen = chunk[1];
      const username = chunk.slice(2, 2 + uLen).toString('utf-8');
      const pLen = chunk[2 + uLen];
      const password = chunk.slice(3 + uLen, 3 + uLen + pLen).toString('utf-8');

      if (proxyUsers.has(username) && proxyUsers.get(username) === password) {
        socksState = 2;
        clientSocket.write(Buffer.from([0x01, 0x00]));
      } else {
        clientSocket.write(Buffer.from([0x01, 0x01]));
        return clientSocket.end();
      }
      return;
    }

    if (socksState === 2) {
      if (chunk[0] !== 0x05 || chunk[1] !== 0x01) {
        clientSocket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return clientSocket.end();
      }

      let targetHost = '';
      let targetPort = 0;
      const atyp = chunk[3];

      if (atyp === 0x01) {
        targetHost = `${chunk[4]}.${chunk[5]}.${chunk[6]}.${chunk[7]}`;
        targetPort = chunk.readUInt16BE(8);
      } else if (atyp === 0x03) {
        const dLen = chunk[4];
        targetHost = chunk.slice(5, 5 + dLen).toString('utf-8');
        targetPort = chunk.readUInt16BE(5 + dLen);
      } else {
        clientSocket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        return clientSocket.end();
      }

      connData.type = 'SOCKS5';
      connData.target = `${targetHost}:${targetPort}`;
      activeConnections.set(connId, connData);

      try {
        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x10, 0x10]));
          clientSocket.removeAllListeners('data');
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => {
          activeConnections.delete(connId);
          clientSocket.destroy();
        });
      } catch (err) {
        clientSocket.write(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        clientSocket.end();
      }
    }
  };

  clientSocket.on('data', async (chunk) => {
    if (socksState > 0) return handleSocks5(chunk);

    if (isFirstPacket) {
      if (chunk[0] === 0x05) {
        isFirstPacket = false;
        return handleSocks5(chunk);
      }

      const chunkStr = chunk.toString('utf-8');

      // 1. HTTP REQUEST / DASHBOARD / API / WEBSOCKET UPGRADE
      if (/^(GET|POST|PUT|DELETE|OPTIONS|HEAD)\s/i.test(chunkStr)) {
        httpBuffer += chunkStr;

        const contentLenMatch = httpBuffer.match(/Content-Length:\s*(\d+)/i);
        const headerEnd = httpBuffer.indexOf('\r\n\r\n');
        
        if (contentLenMatch && headerEnd !== -1) {
          const expectedLen = parseInt(contentLenMatch[1], 10);
          const bodyLen = Buffer.byteLength(httpBuffer.slice(headerEnd + 4));
          if (bodyLen < expectedLen) return;
        } else if (headerEnd === -1 && httpBuffer.startsWith('POST')) {
          return;
        }

        isFirstPacket = false;
        const dataStr = httpBuffer;
        const firstLine = dataStr.split('\r\n')[0];
        const pathUrl = firstLine.split(' ')[1] || '/';

        // WEBSOCKET UPGRADE UNTUK UDP RELAY
        if (/Upgrade:\s*websocket/i.test(dataStr)) {
          const keyMatch = dataStr.match(/Sec-WebSocket-Key:\s*([^\r\n]+)/i);
          if (keyMatch) {
            const key = keyMatch[1].trim();
            const accept = websocketAccept(key);
            clientSocket.write(
              'HTTP/1.1 101 Switching Protocols\r\n' +
              'Upgrade: websocket\r\n' +
              'Connection: Upgrade\r\n' +
              `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
            );

            UDP_STATS.totalHandshakes++;
            UDP_STATS.activeClients++;
            let counted = true;

            const ws = new WebSocketRelaySocket(clientSocket, UDP_CONFIG.MAX_WS_MESSAGE_BYTES);
            ws.once('close', () => {
              if (counted) {
                counted = false;
                UDP_STATS.activeClients--;
                addUdpLog(`[DISCONNECT] Klien terputus. Sisa: ${UDP_STATS.activeClients}`);
              }
            });

            const rest = Buffer.from(httpBuffer.slice(headerEnd + 4));
            if (rest.length > 0) ws.feedHead(rest);

            handleConnectionUDP(ws, UDP_CONFIG).catch(() => ws.destroy());
            return;
          }
        }

        // API: Set DNS
        if (pathUrl.startsWith('/api/set-dns') && dataStr.startsWith('POST')) {
          try {
            const body = parseRequestBody(dataStr);
            if (body.preset && PRESETS[body.preset]) {
              const p = PRESETS[body.preset];
              DNS_CONFIG.mode = p.type;
              DNS_CONFIG.activeName = p.name;
              if (p.type === 'DOH') DNS_CONFIG.dohUrl = p.url;
              else { DNS_CONFIG.udpServer = p.host; DNS_CONFIG.udpPort = p.port; }
            } else if (body.mode === 'DOH') {
              DNS_CONFIG.mode = 'DOH';
              DNS_CONFIG.activeName = 'Custom DoH';
              DNS_CONFIG.dohUrl = body.dohUrl || 'https://cloudflare-dns.com/dns-query';
            } else if (body.mode === 'UDP') {
              DNS_CONFIG.mode = 'UDP';
              DNS_CONFIG.activeName = 'Custom UDP';
              DNS_CONFIG.udpServer = body.udpServer || '1.1.1.1';
              DNS_CONFIG.udpPort = parseInt(body.udpPort, 10) || 53;
            }
            saveData();
            dnsCache.clear();
            const resBody = JSON.stringify({ success: true, config: DNS_CONFIG });
            clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } catch (e) {
            const errBody = JSON.stringify({ success: false, error: e.message });
            clientSocket.write(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: ${errBody.length}\r\nConnection: close\r\n\r\n${errBody}`);
          }
          clientSocket.end();
          return;
        }

        // API: Set RAW TCP
        if (pathUrl === '/api/set-raw-tcp' && dataStr.startsWith('POST')) {
          const body = parseRequestBody(dataStr);
          RAW_TCP_CONFIG.enabled = !!body.enabled;
          if (body.defaultTargetHost) RAW_TCP_CONFIG.defaultTargetHost = body.defaultTargetHost.trim();
          if (body.defaultTargetPort) RAW_TCP_CONFIG.defaultTargetPort = parseInt(body.defaultTargetPort, 10) || 443;
          saveData();
          const resBody = JSON.stringify({ success: true, config: RAW_TCP_CONFIG });
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // API: Manage Users
        if (pathUrl === '/api/manage-users' && dataStr.startsWith('POST')) {
          const body = parseRequestBody(dataStr);
          if (body.action === 'add' && body.username && body.password) {
            proxyUsers.set(body.username.trim(), body.password.trim());
            saveData();
          } else if (body.action === 'delete' && body.username) {
            proxyUsers.delete(body.username);
            saveData();
          } else if (body.action === 'set-mode' && body.mode) {
            PROXY_AUTH_MODE = body.mode;
            saveData();
          }
          const resBody = JSON.stringify({ success: true });
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // API: Stats Realtime Auto-Scale
        if (pathUrl === '/api/stats') {
          const activeList = Array.from(activeConnections.values())
            .filter(c => !c.target.includes('railway.com') && !c.target.includes('up.railway.app'))
            .map(c => ({
              id: c.id,
              clientIp: c.clientIp,
              type: c.type,
              target: c.target,
              uptime: Math.floor((Date.now() - c.startTime) / 1000),
              bytesIn: formatDynamicBytes(c.bytesIn),
              bytesOut: formatDynamicBytes(c.bytesOut)
            }));

          const userObjects = [];
          proxyUsers.forEach((pass, user) => userObjects.push({ username: user, password: pass }));

          const resBody = JSON.stringify({
            udp: {
              activeClients: UDP_STATS.activeClients,
              totalHandshakes: UDP_STATS.totalHandshakes,
              packetsIn: UDP_STATS.udpPacketsIn,
              packetsOut: UDP_STATS.udpPacketsOut,
              bytesInDisplay: formatDynamicBytes(UDP_STATS.udpBytesIn),
              bytesOutDisplay: formatDynamicBytes(UDP_STATS.udpBytesOut),
              recentLogs: UDP_STATS.recentLogs
            },
            proxy: {
              info: PROXY_SERVER_INFO,
              dnsConfig: DNS_CONFIG,
              rawTcpConfig: RAW_TCP_CONFIG,
              authMode: PROXY_AUTH_MODE,
              userList: userObjects,
              totalActive: activeList.length,
              bytesInDisplay: formatDynamicBytes(proxyBytesIn),
              bytesOutDisplay: formatDynamicBytes(proxyBytesOut),
              connections: activeList
            }
          });

          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ${Buffer.byteLength(resBody)}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // DASHBOARD WEB UI
        const hostHeaderMatch = dataStr.match(/Host:\s*([^\r\n:]+)/i);
        const reqHost = hostHeaderMatch ? hostHeaderMatch[1].trim() : '';
        const isInternalHost = reqHost.includes('railway.app') || reqHost.includes('railway.com') || reqHost.includes('localhost') || reqHost.includes('127.0.0.1');

        if (pathUrl === '/' || pathUrl === '/index.html' || isInternalHost) {
          const html = renderDashboardHTML();
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\nConnection: close\r\n\r\n${html}`);
          clientSocket.end();
          return;
        }

        // HTTP Forward Proxy
        if (!checkHttpAuth(dataStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        connData.type = 'HTTP SCAN';
        connData.target = `${targetHost}:${targetPort}`;
        activeConnections.set(connId, connData);

        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          targetSocket.write(Buffer.from(httpBuffer));
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
        return;
      }

      isFirstPacket = false;

      // 2. HTTPS CONNECT PROXY (SNI SNIFFER AKTIF)
      if (chunkStr.startsWith('CONNECT ')) {
        if (!checkHttpAuth(chunkStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const match = chunkStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;

          if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
            connData.type = 'HTTPS TUNNEL';
            connData.target = `${targetHost}:${targetPort}`;
            activeConnections.set(connId, connData);
          }

          const resolvedIp = await resolveDomain(targetHost);
          targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
            targetSocket.setNoDelay(true);
            targetSocket.setKeepAlive(true, 5000);
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

            // Intip paket TLS Client Hello untuk ekstrak domain asli
            clientSocket.once('data', (tlsChunk) => {
              const extractedSni = parseTlsSni(tlsChunk);
              if (extractedSni) {
                connData.target = `${extractedSni}:${targetPort}`;
                activeConnections.set(connId, connData);
              }
              if (!targetSocket.destroyed) {
                targetSocket.write(tlsChunk);
              }
              bridgeSockets(clientSocket, targetSocket);
            });
          });

          targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
          return;
        }
      }

      // 3. RAW TCP / VLESS / TROJAN / SNI ROUTER
      const sni = parseTlsSni(chunk);
      let destinationHost = '';
      let destinationPort = 443;

      if (sni) {
        destinationHost = sni;
        connData.type = 'VLESS/TLS (SNI)';
      } else if (RAW_TCP_CONFIG.enabled) {
        destinationHost = RAW_TCP_CONFIG.defaultTargetHost;
        destinationPort = RAW_TCP_CONFIG.defaultTargetPort;
        connData.type = 'RAW TCP MENTAH';
      } else {
        destinationHost = 'speed.cloudflare.com';
        connData.type = 'DIRECT FALLBACK';
      }

      connData.target = `${destinationHost}:${destinationPort}`;
      activeConnections.set(connId, connData);

      const resolvedIp = await resolveDomain(destinationHost);
      targetSocket = net.connect({ host: resolvedIp, port: destinationPort, noDelay: true }, () => {
        targetSocket.setNoDelay(true);
        targetSocket.setKeepAlive(true, 5000);
        targetSocket.write(chunk);
        bridgeSockets(clientSocket, targetSocket);
      });

      targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
    }
  });

  clientSocket.on('error', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
  clientSocket.on('close', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
}

// ==========================================
// 7. START LISTENERS (PORT 8080 & PORT 8081)
// ==========================================
const mainServer = net.createServer({
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, setupConnectionHandler);

mainServer.on('error', (err) => {
  console.error(`[Main Server Error on Port ${MAIN_PORT}]:`, err.message);
});

mainServer.listen(MAIN_PORT, '0.0.0.0', () => {
  console.log(`[Unified Server] Running on port ${MAIN_PORT}`);
  addUdpLog(`Unified Server running on port ${MAIN_PORT}`);
});

const extraTcpServer = net.createServer({
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, setupConnectionHandler);

extraTcpServer.on('error', (err) => {
  console.error(`[Extra TCP Server Error on Port ${EXTRA_TCP_PORT}]:`, err.message);
});

extraTcpServer.listen(EXTRA_TCP_PORT, '0.0.0.0', () => {
  console.log(`[Extra TCP Server] Running on port ${EXTRA_TCP_PORT}`);
});
