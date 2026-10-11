'use strict';
// HARNESS-side reader for the OOB sink (the "legitimate user's inbox"). Uses the READ key, which the
// application never has. Every OTT it returns is remembered so tests can scan stored data for leaks.
const seen = new Set();

function createSinkClient({ baseUrl, readKey }) {
  const headers = { 'x-sink-key': readKey };
  const readAll = async (userId) => {
    const r = await fetch(`${baseUrl}/inbox/${userId}`, { headers });
    if (r.status !== 200) throw new Error(`sink read failed: ${r.status}`);
    const msgs = await r.json();
    msgs.forEach((m) => seen.add(m.token));
    return msgs;
  };
  /** Poll (20 ms, up to timeoutMs) until at least `count` messages arrived; returns them in arrival order. */
  const waitFor = async (userId, count = 1, timeoutMs = 2000) => {
    const got = [];
    const t0 = Date.now();
    while (got.length < count && Date.now() - t0 < timeoutMs) {
      got.push(...(await readAll(userId)));
      if (got.length < count) await new Promise((r) => setTimeout(r, 20));
    }
    if (got.length < count) throw new Error(`expected ${count} OOB message(s), got ${got.length}`);
    return got;
  };
  const readOtt = async (userId) => (await waitFor(userId, 1))[0].token;
  const reset = () => fetch(`${baseUrl}/reset`, { method: 'POST', headers });
  return { readAll, waitFor, readOtt, reset, seen };
}

module.exports = { createSinkClient };
