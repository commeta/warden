// Warden Lab microservice — WebSocket (Node stdlib http + crypto handshake).
// GET /health returns ok over HTTP; an Upgrade request opens a WS that echoes
// text frames. Exercises the WAF/front Upgrade path.
'use strict';
const http = require('http');
const crypto = require('crypto');
const PORT = parseInt(process.env.PORT || '3109', 10);
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const server = http.createServer((req, res) => {
  const p = req.url.replace(/^\/svc\/[^/]+/, '') || '/';
  res.setHeader('X-Lab-Service', 'ws');
  if (p === '/health') { res.end('ok'); return; }
  res.statusCode = 426; res.end('upgrade required');
});
server.on('upgrade', (req, sock) => {
  const key = req.headers['sec-websocket-key'] || '';
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n' +
             'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  sock.on('data', (buf) => {
    // decode one text frame, echo it back unmasked
    if (buf.length < 2) return;
    const len = buf[1] & 0x7f;
    let off = 2, mask = null;
    if (buf[1] & 0x80) { mask = buf.slice(off, off + 4); off += 4; }
    const payload = buf.slice(off, off + len);
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    const out = Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
    sock.write(out);
  });
  sock.on('error', () => {});
});
server.listen(PORT, '127.0.0.1', () => console.log('ws lab svc on ' + PORT));
