import { randomBytes } from 'node:crypto';
import net from 'node:net';
import {
  TCP_FLAGS,
  buildTCPPacket,
  buildSynAckOptions,
  parseIPPacket,
  parseTcpSynOptions,
} from '../../src/network/packet.js';
import { PROBE_MARKER } from './transport-test-probes.mjs';

/** @param {string} ip */
function ip4Bytes(ip) {
  return ip.split('.').map((x) => parseInt(x, 10));
}

function internetChecksum16(buf, off, len) {
  let sum = 0;
  const end = off + len;
  for (let i = off; i + 1 < end; i += 2) sum += buf.readUInt16BE(i);
  if (len % 2) sum += buf[end - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/**
 * @param {number[]} src4
 * @param {number[]} dst4
 * @param {number} id
 * @param {number} seq
 */
function buildIcmpEchoRequest(src4, dst4, id, seq) {
  const icmpLen = 8;
  const icmp = Buffer.allocUnsafe(icmpLen);
  icmp.writeUInt8(8, 0);
  icmp.writeUInt8(0, 1);
  icmp.writeUInt16BE(id, 4);
  icmp.writeUInt16BE(seq, 6);
  icmp.writeUInt16BE(internetChecksum16(icmp, 0, icmpLen), 2);

  const ip = Buffer.allocUnsafe(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt16BE(20 + icmpLen, 2);
  ip.writeUInt16BE(randomBytes(2).readUInt16BE(0), 4);
  ip.writeUInt16BE(0, 6);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(1, 9);
  for (let i = 0; i < 4; i++) {
    ip.writeUInt8(src4[i], 12 + i);
    ip.writeUInt8(dst4[i], 16 + i);
  }
  ip.writeUInt16BE(internetChecksum16(ip, 0, 20), 10);
  return Buffer.concat([ip, icmp]);
}

/**
 * @param {Buffer} pkt
 * @param {string} peerIp
 * @param {string} localIp
 * @param {number} id
 * @param {number} seq
 */
function isIcmpEchoReply(pkt, peerIp, localIp, id, seq) {
  const p = parseIPPacket(pkt);
  if (!p?.valid || p.protocol !== 1) return false;
  if (p.srcIp !== peerIp || p.dstIp !== localIp) return false;
  if (p.icmpType !== 0) return false;
  const off = p.headerLength;
  if (pkt.length < off + 8) return false;
  return pkt.readUInt16BE(off + 4) === id && pkt.readUInt16BE(off + 6) === seq;
}

/**
 * @param {{ localIp: string, localProbePort: number }} opts
 */
export function createTransportTestWireProbes(opts) {
  const localIp = opts.localIp;
  const localProbePort = opts.localProbePort;
  const local4 = ip4Bytes(localIp);

  /** @type {{ id: number, seq: number, peerIp: string, t0: number, resolve: (s: string) => void, reject: (e: Error) => void, timer: NodeJS.Timeout } | null} */
  let icmpPending = null;

  /** @type {Map<string, ServerConn>} */
  const tcpServers = new Map();
  /** @type {Map<number, ClientConn>} */
  const tcpClients = new Map();

  /**
   * @param {Buffer} pkt
   * @param {(pkt: Buffer) => void} sendOnWire
   */
  function tryConsumeInboundWire(pkt, sendOnWire) {
    if (
      icmpPending &&
      isIcmpEchoReply(pkt, icmpPending.peerIp, localIp, icmpPending.id, icmpPending.seq)
    ) {
      const ms = Date.now() - icmpPending.t0;
      clearTimeout(icmpPending.timer);
      icmpPending.resolve(`${localIp}↔${icmpPending.peerIp} wire-icmp ${ms}ms`);
      icmpPending = null;
      return true;
    }

    const p = parseIPPacket(pkt);
    if (!p?.valid || p.protocol !== 6 || p.dstIp !== localIp) return false;

    if (p.dstPort === localProbePort) {
      return handleTcpServerInbound(p, pkt, sendOnWire);
    }
    const client = tcpClients.get(p.dstPort);
    if (client) {
      return handleTcpClientInbound(client, p, sendOnWire);
    }
    return false;
  }

  /**
   * @param {ReturnType<typeof parseIPPacket>} p
   * @param {Buffer} pkt
   * @param {(pkt: Buffer) => void} sendOnWire
   */
  function handleTcpServerInbound(p, pkt, sendOnWire) {
    const key = `${p.srcIp}:${p.srcPort}`;
    let conn = tcpServers.get(key);

    if (p.tcpFlagsSYN && !p.tcpFlagsACK) {
      const synOpts = parseTcpSynOptions(pkt);
      const serverSeq = randomBytes(4).readUInt32BE(0);
      conn = {
        srcIp: p.srcIp,
        srcPort: p.srcPort,
        clientSeq: p.tcpSeq,
        clientAck: p.tcpSeq + 1,
        serverSeq: (serverSeq + 1) >>> 0,
        state: 'SYN_RCVD',
        socket: null,
      };
      tcpServers.set(key, conn);
      sendOnWire(
        buildTCPPacket(
          localIp,
          p.srcIp,
          localProbePort,
          p.srcPort,
          serverSeq,
          p.tcpSeq + 1,
          TCP_FLAGS.SYN | TCP_FLAGS.ACK,
          Buffer.alloc(0),
          buildSynAckOptions(synOpts),
        ),
      );
      return true;
    }

    if (!conn) return false;
    if (p.tcpFlagsRST) {
      tcpServers.delete(key);
      conn.socket?.destroy();
      return true;
    }

    if (p.tcpFlagsACK && conn.state === 'SYN_RCVD') {
      conn.state = 'ESTABLISHED';
      conn.clientAck = Math.max(conn.clientAck, p.tcpAck >>> 0);
      openLocalHttp(conn, sendOnWire);
      return true;
    }

    if (conn.state === 'ESTABLISHED' && p.data.length) {
      conn.clientAck = (p.tcpSeq + p.data.length) >>> 0;
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.srcIp,
          localProbePort,
          conn.srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.ACK,
        ),
      );
      return true;
    }

    if (p.tcpFlagsFIN) {
      conn.clientAck = (p.tcpSeq + 1) >>> 0;
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.srcIp,
          localProbePort,
          conn.srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.ACK,
        ),
      );
      conn.socket?.end();
      setTimeout(() => tcpServers.delete(key), 5000).unref?.();
      return true;
    }

    return true;
  }

  /** @param {ClientConn} conn @param {ReturnType<typeof parseIPPacket>} p @param {(pkt: Buffer) => void} sendOnWire */
  function handleTcpClientInbound(conn, p, sendOnWire) {
    if (p.srcIp !== conn.peerIp || p.srcPort !== conn.peerPort) return false;

    if (p.tcpFlagsRST) {
      clearTimeout(conn.timer);
      tcpClients.delete(conn.localPort);
      conn.reject(new Error(`tcp reset ${conn.peerIp}:${conn.peerPort}`));
      return true;
    }

    if (p.tcpFlagsSYN && p.tcpFlagsACK && conn.state === 'SYN_SENT') {
      conn.state = 'ESTABLISHED';
      conn.clientAck = (p.tcpSeq + 1) >>> 0;
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.peerIp,
          conn.localPort,
          conn.peerPort,
          conn.clientSeq + 1,
          conn.clientAck,
          TCP_FLAGS.ACK,
        ),
      );
      conn.clientSeq += 1;
      const req = `GET / HTTP/1.1\r\nHost: ${conn.peerIp}\r\nConnection: close\r\n\r\n`;
      const body = Buffer.from(req);
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.peerIp,
          conn.localPort,
          conn.peerPort,
          conn.clientSeq,
          conn.clientAck,
          TCP_FLAGS.PSH | TCP_FLAGS.ACK,
          body,
        ),
      );
      conn.clientSeq = (conn.clientSeq + body.length) >>> 0;
      return true;
    }

    if (conn.state !== 'ESTABLISHED') return false;

    if (p.data.length) {
      conn.rxBuf = Buffer.concat([conn.rxBuf, p.data]);
      conn.clientAck = (p.tcpSeq + p.data.length) >>> 0;
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.peerIp,
          conn.localPort,
          conn.peerPort,
          conn.clientSeq,
          conn.clientAck,
          TCP_FLAGS.ACK,
        ),
      );
    }

    if (p.tcpFlagsFIN) {
      conn.clientAck = (p.tcpSeq + 1) >>> 0;
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.peerIp,
          conn.localPort,
          conn.peerPort,
          conn.clientSeq,
          conn.clientAck,
          TCP_FLAGS.ACK,
        ),
      );
      finishHttpClient(conn);
      return true;
    }

    if (conn.rxBuf.includes(PROBE_MARKER)) {
      finishHttpClient(conn);
      return true;
    }

    return true;
  }

  /** @param {ServerConn} conn @param {(pkt: Buffer) => void} sendOnWire */
  function openLocalHttp(conn, sendOnWire) {
    const sock = net.connect({ port: localProbePort, host: '127.0.0.1' });
    conn.socket = sock;
    sock.on('connect', () => {
      sock.write(`GET / HTTP/1.1\r\nHost: ${localIp}\r\nConnection: close\r\n\r\n`);
    });
    sock.on('data', (chunk) => {
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.srcIp,
          localProbePort,
          conn.srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.PSH | TCP_FLAGS.ACK,
          chunk,
        ),
      );
      conn.serverSeq = (conn.serverSeq + chunk.length) >>> 0;
    });
    sock.on('end', () => {
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.srcIp,
          localProbePort,
          conn.srcPort,
          conn.serverSeq,
          conn.clientAck,
          TCP_FLAGS.FIN | TCP_FLAGS.ACK,
        ),
      );
      conn.serverSeq += 1;
    });
    sock.on('error', () => {
      sendOnWire(
        buildTCPPacket(
          localIp,
          conn.srcIp,
          localProbePort,
          conn.srcPort,
          0,
          0,
          TCP_FLAGS.RST,
        ),
      );
    });
  }

  /** @param {ClientConn} conn */
  function finishHttpClient(conn) {
    const body = conn.rxBuf.toString('latin1');
    clearTimeout(conn.timer);
    tcpClients.delete(conn.localPort);
    if (!body.includes(PROBE_MARKER)) {
      conn.reject(new Error(`missing marker from ${conn.peerIp}:${conn.peerPort}`));
      return;
    }
    conn.resolve(`${localIp}→${conn.peerIp}:${conn.peerPort} wire-http (${PROBE_MARKER})`);
  }

  /**
   * @param {string} peerIp
   * @param {(pkt: Buffer) => void} writeTun
   * @param {(pkt: Buffer) => void} sendOnWire
   */
  function pingPeer(peerIp, writeTun, sendOnWire) {
    const id = randomBytes(2).readUInt16BE(0);
    const seq = 1;
    const req = buildIcmpEchoRequest(local4, ip4Bytes(peerIp), id, seq);
    const t0 = Date.now();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        icmpPending = null;
        reject(new Error(`icmp timeout ${localIp}→${peerIp}`));
      }, 12000);
      timer.unref?.();
      icmpPending = { id, seq, peerIp, t0, resolve, reject, timer };
      writeTun(req);
      setTimeout(() => {
        if (icmpPending?.id === id) sendOnWire(req);
      }, 120).unref?.();
    });
  }

  /**
   * @param {string} peerIp
   * @param {number} peerPort
   * @param {(pkt: Buffer) => void} writeTun
   * @param {(pkt: Buffer) => void} sendOnWire
   */
  function httpGetPeer(peerIp, peerPort, writeTun, sendOnWire) {
    const localPort = 40000 + (randomBytes(2).readUInt16BE(0) % 20000);
    const clientSeq = randomBytes(4).readUInt32BE(0);
    /** @type {ClientConn} */
    const conn = {
      peerIp,
      peerPort,
      localPort,
      clientSeq,
      clientAck: 0,
      state: 'SYN_SENT',
      rxBuf: Buffer.alloc(0),
      resolve: () => {},
      reject: () => {},
      timer: setTimeout(() => {}, 0),
    };
    tcpClients.set(localPort, conn);

    const syn = buildTCPPacket(localIp, peerIp, localPort, peerPort, clientSeq, 0, TCP_FLAGS.SYN);

    return new Promise((resolve, reject) => {
      conn.resolve = resolve;
      conn.reject = reject;
      conn.timer = setTimeout(() => {
        tcpClients.delete(localPort);
        reject(new Error(`http timeout ${localIp}→${peerIp}:${peerPort}`));
      }, 12000);
      conn.timer.unref?.();

      // TCP через wire (writeTun на macOS same-host не гарантирует egress в мост).
      sendOnWire(syn);
    });
  }

  return { tryConsumeInboundWire, pingPeer, httpGetPeer };
}

/** @typedef {{ srcIp: string, srcPort: number, clientSeq: number, clientAck: number, serverSeq: number, state: string, socket: import('net').Socket|null }} ServerConn */
/** @typedef {{ peerIp: string, peerPort: number, localPort: number, clientSeq: number, clientAck: number, state: string, rxBuf: Buffer, resolve: (s: string) => void, reject: (e: Error) => void, timer: NodeJS.Timeout }} ClientConn */
