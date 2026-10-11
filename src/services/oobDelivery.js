'use strict';
// Application-side handoff to the OOB sink: one keep-alive HTTP POST on loopback, authenticated by the
// DELIVER key. Called after the OTT transaction has committed and NOT awaited by the request, so the HTTP
// response is not delayed by delivery. Its CPU/event-loop cost is part of Config C's measured cost
// (EXPERIMENTS.md 6). Never logs the token.
function createOobDelivery({ config }) {
  const { url, deliverKey } = config.oobSink;
  return {
    async deliver({ userId, operation, purpose, token }) {
      const res = await fetch(`${url}/deliver`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-sink-key': deliverKey },
        body: JSON.stringify({ userId: String(userId), operation, purpose, token }),
        signal: AbortSignal.timeout(2000),
      });
      await res.arrayBuffer(); // drain so the keep-alive connection is reused
      if (!res.ok) { const e = new Error(`sink status ${res.status}`); e.reason = `SINK_STATUS_${res.status}`; throw e; }
    },
  };
}

/** Map a delivery error to a short, secret-free reason. */
function deliveryFailureReason(e) {
  if (e && e.reason) return e.reason;
  if (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) return 'SINK_TIMEOUT';
  return 'SINK_UNREACHABLE';
}

module.exports = { createOobDelivery, deliveryFailureReason };
