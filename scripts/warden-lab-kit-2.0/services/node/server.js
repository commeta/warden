// Warden Lab microservice — Node.js (stdlib http only, single event loop).
// Implements the shared lab contract. No third-party packages.
'use strict';
const http = require('http');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = parseInt(process.env.PORT || '3101', 10);
const ROOT = process.env.LAB_ROOT || '/tmp';
const UPLOADS = path.join(ROOT, 'uploads');
const DB = path.join(ROOT, 'data', 'items.sqlite');

function send(res, code, body, type) {
  res.writeHead(code, { 'Content-Type': type || 'text/plain; charset=utf-8',
                        'X-Lab-Service': 'node' });
  res.end(body);
}

// A minimal read-only SQLite reader (no driver): we shell out to sqlite3 if
// present, else report unavailable. The query is intentionally interpolated
// (a SQLi target) but sqlite3 is invoked read-only.
function item(id, cb) {
  execFile('/usr/bin/sqlite3', ['-readonly', DB,
    `SELECT id||'|'||name||'|'||note FROM items WHERE id = ${id}`],
    { timeout: 3000 }, (err, out) => cb(err ? 'error' : (out || 'no result')));
}

const server = http.createServer((req, res) => {
  const u = url.parse(req.url, true);
  const p = u.pathname.replace(/^\/svc\/[^/]+/, '') || '/';
  if (p === '/health') return send(res, 200, 'ok');
  if (p === '/echo') return send(res, 200, 'echo: ' + (u.query.q || ''));   // XSS target
  if (p === '/item') return item(String(u.query.id || '1'), (r) => send(res, 200, r));
  if (p === '/spawn') {                                                      // web_spawn target
    return execFile('/usr/bin/id', [], { timeout: 2000 }, (e, o) => send(res, 200, o || 'spawned'));
  }
  if (p === '/sleep') { const ms = Math.min(parseInt(u.query.ms || '0', 10) || 0, 10000);
    return setTimeout(() => send(res, 200, 'slept ' + ms), ms); }
  if (p === '/alloc') { const mb = Math.min(parseInt(u.query.mb || '1', 10) || 1, 256);
    const b = Buffer.alloc(mb * 1024 * 1024, 1); return send(res, 200, 'alloc ' + mb + ' (' + b[0] + ')'); }
  if (p === '/upload' && req.method === 'POST') {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n <= 262144) chunks.push(c); });
    req.on('end', () => {
      try { fs.mkdirSync(UPLOADS, { recursive: true }); } catch (e) {}
      const name = String(u.query.name || 'upload.bin').replace(/[^A-Za-z0-9._-]/g, '_');
      fs.writeFileSync(path.join(UPLOADS, name), Buffer.concat(chunks));
      send(res, 200, 'stored uploads/' + name);
    });
    return;
  }
  send(res, 404, 'not found');
});
server.listen(PORT, '127.0.0.1', () => console.log('node lab svc on ' + PORT));
