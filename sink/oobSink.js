'use strict';
// Simulated out-of-band delivery channel (EXPERIMENTS.md section 6). TEST INFRASTRUCTURE: not part of the
// system under test and not an application data model.
//   POST /deliver        (x-sink-key = deliver key)  app hands over a message         -> 202
//   GET  /inbox/:userId  (x-sink-key = read key)     harness reads AND DELETES        -> 200 [messages]
//   POST /reset          (x-sink-key = read key)     clear everything before a run    -> 204
//   GET  /health                                                                       -> 200
// The two keys are different on purpose: the application can deliver but can never read the inbox.
const http = require('http');
const crypto = require('crypto');

const eq = (a, b) => {
  const x = Buffer.from(String(a || '')); const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function createSink({ deliverKey, readKey, maxPerUser = 100 }) {
  if (!deliverKey || !readKey || deliverKey === readKey) throw new Error('sink needs two different keys');
  const inbox = new Map(); // userId -> [{ operation, purpose, token, receivedAt }]
  const stats = { delivered: 0, read: 0 };

  const json = (res, status, body) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
    res.end(data);
  };
  const readBody = (req) => new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 4096) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://sink');
      const key = req.headers['x-sink-key'];
      if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { status: 'ok' });

      if (req.method === 'POST' && url.pathname === '/deliver') {
        if (!eq(key, deliverKey)) return json(res, 401, { error: 'unauthorized' });
        let m;
        try { m = JSON.parse(await readBody(req)); } catch (e) { return json(res, 400, { error: 'bad body' }); }
        if (!m || typeof m.userId === 'undefined' || typeof m.token !== 'string' || typeof m.operation !== 'string') {
          return json(res, 400, { error: 'bad message' });
        }
        const id = String(m.userId);
        const list = inbox.get(id) || [];
        list.push({ operation: m.operation, purpose: m.purpose, token: m.token, receivedAt: Date.now() });
        while (list.length > maxPerUser) list.shift(); // bounded memory if nobody reads
        inbox.set(id, list);
        stats.delivered += 1;
        return json(res, 202, { status: 'accepted' });
      }

      const m = /^\/inbox\/([^/]+)$/.exec(url.pathname);
      if (req.method === 'GET' && m) {
        if (!eq(key, readKey)) return json(res, 401, { error: 'unauthorized' });
        const id = decodeURIComponent(m[1]);
        const list = inbox.get(id) || [];
        inbox.delete(id); // delete-on-read
        stats.read += list.length;
        return json(res, 200, list);
      }

      if (req.method === 'POST' && url.pathname === '/reset') {
        if (!eq(key, readKey)) return json(res, 401, { error: 'unauthorized' });
        inbox.clear(); stats.delivered = 0; stats.read = 0;
        return json(res, 204);
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) {
      return json(res, 500, { error: 'sink error' });
    }
  });
  server.keepAliveTimeout = 30000;

  return {
    server, stats,
    listen: (port = 0, host = '127.0.0.1') => new Promise((resolve) => server.listen(port, host, () => resolve(server.address().port))),
    close: () => new Promise((resolve) => { server.closeAllConnections && server.closeAllConnections(); server.close(resolve); }),
    size: () => [...inbox.values()].reduce((n, l) => n + l.length, 0),
  };
}

module.exports = { createSink };
