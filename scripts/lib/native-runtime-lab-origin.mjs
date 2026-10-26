// Isolated fixture services. Only the lab network can reach these listeners.
import net from 'node:net';
import dgram from 'node:dgram';
import https from 'node:https';
import fs from 'node:fs';
const response = q => {
  const b = Buffer.from(q); b.writeUInt16BE(0x8180, 2); b.writeUInt16BE(1, 6);
  return Buffer.concat([b, Buffer.from('c00c00010001000000010004c6120050', 'hex')]); // 198.18.0.80
};
const udp = dgram.createSocket('udp4');
udp.on('message', (b, r) => udp.send(response(b), r.port, r.address)); udp.bind(5353, '0.0.0.0');
net.createServer(s => { let b = Buffer.alloc(0); s.on('data', chunk => {
  b = Buffer.concat([b, chunk]); if (b.length < 2 || b.length < 2 + b.readUInt16BE(0)) return;
  const r = response(b.subarray(2, 2 + b.readUInt16BE(0))), n = Buffer.alloc(2); n.writeUInt16BE(r.length); s.end(Buffer.concat([n, r]));
}); }).listen(5353, '0.0.0.0');
net.createServer(s => s.pipe(s)).listen(8080, '0.0.0.0');
const echo = dgram.createSocket('udp4'); echo.on('message', (b, r) => echo.send(b, r.port, r.address)); echo.bind(8081, '198.18.0.80');
https.createServer({ key: fs.readFileSync('/config/key.pem'), cert: fs.readFileSync('/config/cert.pem') },
  (req, res) => { res.end('native-runtime-https-ok\n'); }).listen(8443, '0.0.0.0');
console.log('ORIGIN_READY');
