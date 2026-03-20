/**
 * CROCbox v0.8 — WebSocket MITM Proxy (ws-proxy.js)
 * 
 * Launch Checklist A.7 + A.8 + A.10-R:
 *   A.7: Auth token auto-injected (no manual paste)
 *   A.8: WebSocket MITM proxy relays all messages transparently
 *   A.10-R: Yellow Shield seq-gap detection + consent hold
 * 
 * This module sits between the Control UI and the Gateway, handling:
 * 
 *   1. HTTP: Proxies all requests to the Gateway. For HTML responses,
 *      injects a <script> that: (a) writes the auth token into
 *      localStorage, and (b) overrides WebSocket to redirect from
 *      Gateway port to proxy port. Both execute BEFORE any OpenClaw JS.
 * 
 *   2. WebSocket: Relays all messages transparently in both directions.
 *      On connect requests, rewrites the client type from
 *      openclaw-control-ui to openclaw-macos (token-only auth) and
 *      injects the auth token. This bypasses the device identity
 *      signature mismatch caused by the proxy sitting between the
 *      Control UI and Gateway (different challenge nonces).
 * 
 *   3. YELLOW SHIELD (A.10-R): Detects tool execution via seq-gap in
 *      the agent event stream. When OpenClaw's agent executes a tool,
 *      the node-host consumes tool events internally (seqs 2-4),
 *      creating a gap between lifecycle start (seq 1) and the first
 *      assistant event (seq 5+). The proxy detects this gap, HOLDS the
 *      first assistant event, and signals Electron main process via IPC
 *      for consent. Three paths: Allow (forward held events), Deny
 *      (drop + synthetic message), Timeout (same as Deny).
 *
 *      Yellow Shield = Consent Before Delivery. The action has already
 *      executed. The user decides whether the result is delivered.
 * 
 * CONNECT REWRITE (discovered during A.8 debugging):
 *   The openclaw-control-ui client type requires device identity
 *   (Web Crypto keypair + signature over challenge nonce). Because
 *   the proxy creates a separate upstream WebSocket, the Gateway's
 *   challenge nonce differs from the one the Control UI signed.
 *   Result: signature mismatch → 1008 disconnect.
 *   
 *   Fix: Rewrite the connect request to use openclaw-macos client type,
 *   which requires token-only auth (no device identity). This is the
 *   same client type CROCbox's main process uses. Verified working
 *   in Rosetta Stone recon (March 15, 2026).
 * 
 * @see OPN_ENG_A10-YellowShield_18MAR26_v1 — Yellow Shield architecture
 * @see OPN_ENG_v08-Architecture_15MAR26_v1, Section 3.2
 * @see OPN_ENG_OpenClaw-ATL-Reference_15MAR26_v1, Section 2.3
 * @see OPN_PM_FullCROC-Mode_16MAR26_v2, Section 5
 * @see OPN_ENG_CROC-E2E-Invariants_13MAR26_v2, INV-5
 */
'use strict';
const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');
// ── Configuration ──────────────────────────────────────────────
const PROXY_PORT = 18788;
const GATEWAY_HOST = '127.0.0.1';
const GATEWAY_PORT = 18789;
const GATEWAY_WS = `ws://${GATEWAY_HOST}:${GATEWAY_PORT}`;
// ── State (set by startProxy caller) ───────────────────────────
let authToken = null;
let deviceId = null;
// ── IPC callback (set by main.js after proxy starts) ───────────
// main.js calls setConsentIPC(callback) to wire up the bridge.
// callback signature: (consentRequest) => void
// consentRequest: { holdId, runId, gapSize, heldEventCount, detectedAt }
let consentIPCCallback = null;
function setConsentIPC(callback) {
  consentIPCCallback = callback;
  console.log('[ws-proxy] Consent IPC callback registered');
}
// ── Message Counter ────────────────────────────────────────────
let messageCount = { clientToGateway: 0, gatewayToClient: 0, httpRequests: 0 };
// ── A.10: Pending Approval State (Green Shield — ready if OC enables) ──
// Holds intercepted exec.approval.requested events by ID.
// These are NOT forwarded to the Control UI — CROCbox owns consent.
// Currently dead code for openclaw-macos (Gateway does not broadcast
// exec.approval.requested to this client type). Preserved for Green
// Shield path if OpenClaw enables broadcasts in the future.
const pendingApprovals = new Map();
// ── A.10-R: Yellow Shield State ────────────────────────────────
// Per-runId sequence tracking for seq-gap detection.
// Key: runId (string), Value: { lastSeq, state, holdId }
//   state: 'streaming' (normal) | 'holding' (gap detected, awaiting consent)
//           | 'allowed' (user approved, forwarding) | 'denied' (user denied)
const runState = new Map();
// Held events buffer. Key: holdId (string), Value: {
//   runId, events: [{data, isBinary}], gapSize, detectedAt,
//   clientWs, connId, state: 'pending'|'resolved'
// }
const heldEvents = new Map();
// Consent timeout (ms). Same as existing .env CONSENT_TIMEOUT or 60s default.
const CONSENT_TIMEOUT_MS = parseInt(process.env.CONSENT_TIMEOUT || '60000');
// ── A.12-R: Yellow Shield Audit Logger ─────────────────────────
// Writes consent decisions to the same audit log used by Phase 1/2.
// Maintains the SHA-256 hash chain (INV-8, INV-16).
const AUDIT_LOG_PATH = require('path').join(
  process.env.HOME || '/tmp', 'opnli', 'crocbox', 'logs', 'crocbox-audit.jsonl'
);
function writeYellowShieldAudit(holdId, runId, decision, gapSize, eventCount) {
  try {
    // Read last hash from file
    var prevHash = 'genesis';
    try {
      var lines = require('fs').readFileSync(AUDIT_LOG_PATH, 'utf8').trim().split('\n');
      if (lines.length > 0) {
        var lastEntry = JSON.parse(lines[lines.length - 1]);
        prevHash = lastEntry.hash || 'genesis';
      }
    } catch (e) { /* file may not exist yet */ }

    var reasonMap = {
      'allow': 'user-consent',
      'deny': 'user-deny',
      'timeout': 'user-timeout'
    };
    var resultMap = {
      'allow': 'allowed',
      'deny': 'blocked',
      'timeout': 'blocked'
    };

    var entry = {
      timestamp: new Date().toISOString(),
      action: 'yellow-shield',
      target: 'agent-event-stream',
      result: resultMap[decision] || 'blocked',
      reason: reasonMap[decision] || 'unknown',
      detail: 'seq-gap=' + gapSize + ' events-held=' + eventCount + ' holdId=' + holdId,
      decision_id: holdId,
      shield: 'yellow',
      runId: runId,
      prev_hash: prevHash
    };

    var entryStr = JSON.stringify(entry);
    // Compute hash over entry + prevHash
    entry.hash = crypto.createHash('sha256').update(entryStr + prevHash).digest('hex');

    require('fs').appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + '\n');
    console.log('[ws-proxy] Audit: ' + decision + ' logged (holdId=' + holdId + ')');
  } catch (err) {
    console.error('[ws-proxy] Audit write failed:', err.message);
  }
}
// ── A.10-R: Resolve Consent Decision ──────────────────────────
// Called by main.js IPC handler when user clicks Allow/Deny or timeout fires.
// decision: 'allow' | 'deny' | 'timeout'
function resolveConsent(holdId, decision) {
  const held = heldEvents.get(holdId);
  if (!held) {
    console.log(`[ws-proxy] resolveConsent: holdId ${holdId} not found (already resolved or expired)`);
    return false;
  }
  if (held.state !== 'pending') {
    console.log(`[ws-proxy] resolveConsent: holdId ${holdId} already resolved (${held.state})`);
    return false;
  }
  held.state = decision;
  const run = runState.get(held.runId);
  if (decision === 'allow') {
    // ── ALLOW: Forward all held events, then resume normal streaming ──
    console.log(`[ws-proxy] *** CONSENT ALLOW *** holdId=${holdId} runId=${held.runId} events=${held.events.length}`);
    writeYellowShieldAudit(holdId, held.runId, 'allow', held.gapSize, held.events.length);
    if (run) {
      run.state = 'allowed';
    }
    for (const evt of held.events) {
      if (held.clientWs && held.clientWs.readyState === WebSocket.OPEN) {
        held.clientWs.send(evt.data, { binary: evt.isBinary });
      }
    }
    // Clean up
    heldEvents.delete(holdId);
    return true;
  } else {
    // ── DENY or TIMEOUT: Drop held events, send synthetic message ──
    const reason = decision === 'timeout' ? 'TIMEOUT' : 'DENY';
    console.log(`[ws-proxy] *** CONSENT ${reason} *** holdId=${holdId} runId=${held.runId} dropped=${held.events.length} events`);
    writeYellowShieldAudit(holdId, held.runId, decision, held.gapSize, held.events.length);
    if (run) {
      run.state = 'denied';
    }
    // Send a synthetic agent event so the UI shows something meaningful
    // instead of silence. This appears as a normal assistant text delta.
    if (held.clientWs && held.clientWs.readyState === WebSocket.OPEN) {
      const syntheticEvent = {
        type: 'event',
        event: 'agent',
        payload: {
          type: 'text_delta',
          stream: 'assistant',
          textDelta: '\n\n[CROCbox Yellow Shield] Your AI executed an action, but you chose not to receive the result. CROCbox is protecting your session.\n',
          runId: held.runId,
          seq: 999
        }
      };
      held.clientWs.send(JSON.stringify(syntheticEvent), { binary: false });
    }
    // Clean up
    heldEvents.delete(holdId);
    return true;
  }
}
// ── Injected Script Generator ──────────────────────────────────
function getInjectedScript() {
  const authStore = JSON.stringify({
    version: 1,
    deviceId: deviceId,
    tokens: {
      operator: {
        token: authToken,
        role: 'operator',
        scopes: ['operator.admin', 'operator.approvals', 'operator.pairing'],
        updatedAtMs: Date.now()
      }
    }
  });
  return `<script>
(function() {
  // A.7: Auth token injection
  try {
    localStorage.setItem('openclaw.device.auth.v1', '` + authStore.replace(/'/g, "\\'") + `');
    console.log('[CROCbox] Auth token injected via proxy HTML');
  } catch(e) { console.error('[CROCbox] Auth inject failed:', e); }
  // A.8: WebSocket redirect
  var _WS = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    var u = url;
    if (typeof url === 'string') {
      u = url.replace('://127.0.0.1:` + GATEWAY_PORT + `', '://127.0.0.1:` + PROXY_PORT + `');
      u = u.replace('://localhost:` + GATEWAY_PORT + `', '://localhost:` + PROXY_PORT + `');
      if (u !== url) console.log('[CROCbox] WS redirect: ' + url + ' -> ' + u);
    }
    return protocols !== undefined ? new _WS(u, protocols) : new _WS(u);
  };
  window.WebSocket.prototype = _WS.prototype;
  window.WebSocket.CONNECTING = _WS.CONNECTING;
  window.WebSocket.OPEN = _WS.OPEN;
  window.WebSocket.CLOSING = _WS.CLOSING;
  window.WebSocket.CLOSED = _WS.CLOSED;
  console.log('[CROCbox] WS redirect installed: ` + GATEWAY_PORT + ` -> ` + PROXY_PORT + `');
})();
</script>`;
}
// ── A.11: Consent Card Script Generator ────────────────────────
// Injected in <head>. Creates consent card dynamically when needed.
// Uses polling to wait for both document.body and window.crocbox.
function getConsentCardScript() {
  return `<script>
(function() {
  var CARD_CSS = ''
    + '#cvar f = fs.readFileSyn {'
    + '  position:fixed; top:0; right:0; bottom:0; width:360px; z-index:999999;'
    + '  background:rgba(0,0,0,0.88); backdrop-filter:blur(12px);'
    + '  -webkit-backdrop-filter:blur(12px); border-left:2px solid #d4a017;'
    + '  font-family:-apple-system,BlinkMacSystemFont,sans-serif; color:#f0f0f0;'
    + '  display:flex; flex-direction:column; transition:transform 0.25s ease-out;'
    + '}'
    + '#crocbox-consent-overlay button {'
    + '  flex:1; padding:12px 16px; border:none; border-radius:8px;'
    + '  font-size:14px; font-weight:600; cursor:pointer;'
    + '}'
    + '#crocbox-btn-allow { background:#d4a017; color:#000; }'
    + '#crocbox-btn-deny { background:#333; color:#f0f0f0; border:1px solid #555; }';

  var cardReady = false;

  function ensureStyle() {
    if (document.getElementById('crocbox-consent-style')) return;
    var s = document.createElement('style');
    s.id = 'crocbox-consent-style';
    s.textContent = CARD_CSS;
    (document.head || document.documentElement).appendChild(s);
  }

  function showConsentCard(holdId) {
    ensureStyle();
    // Remove any existing card
    var old = document.getElementById('crocbox-consent-overlay');
    if (old) old.remove();

    var overlay = document.createElement('div');
    overlay.id = 'crocbox-consent-overlay';
    overlay.innerHTML = ''
      + '<div style="padding:20px 24px 16px; border-bottom:1px solid rgba(212,160,23,0.3)">'
      + '  <div style="font-size:48px; margin-bottom:8px">\\u{1F6E1}\\uFE0F</div>'
      + '  <div style="font-size:16px; font-weight:600; color:#d4a017; margin-bottom:4px">Yellow Shield \\u2014 Action Detected</div>'
      + '  <div style="font-size:13px; color:#999">CROCbox detected your AI executed an action</div>'
      + '</div>'
      + '<div style="flex:1; padding:20px 24px">'
      + '  <div style="font-size:13px; color:#ccc; line-height:1.5; margin-bottom:16px">'
      + '    Your AI executed an action. The result is ready but has not been delivered yet.'
      + '    <br><br><strong>You decide what happens next.</strong>'
      + '  </div>'
      + '  <div style="background:rgba(212,160,23,0.1); border:1px solid rgba(212,160,23,0.2); border-radius:8px; padding:12px; font-size:12px; color:#b0b0b0; line-height:1.5">'
      + '    \\u{1F6E1}\\uFE0F <strong>Yellow Shield</strong> means the action already ran. CROCbox controls whether the result reaches you. This is Consent Before Delivery.'
      + '  </div>'
      + '</div>'
      + '<div style="padding:16px 24px 24px; display:flex; gap:12px">'
      + '  <button id="crocbox-btn-allow">Allow Result</button>'
      + '  <button id="crocbox-btn-deny">Block Result</button>'
      + '</div>';

    document.body.appendChild(overlay);
    console.log('[CROCbox] Consent card shown for holdId=' + holdId);

    document.getElementById('crocbox-btn-allow').addEventListener('click', function() {
      console.log('[CROCbox] User clicked ALLOW for holdId=' + holdId);
      overlay.remove();
      if (window.crocbox && window.crocbox.resolveConsent) {
        window.crocbox.resolveConsent(holdId, 'allow');
      }
    });
    document.getElementById('crocbox-btn-deny').addEventListener('click', function() {
      console.log('[CROCbox] User clicked DENY for holdId=' + holdId);
      overlay.remove();
      if (window.crocbox && window.crocbox.resolveConsent) {
        window.crocbox.resolveConsent(holdId, 'deny');
      }
    });
  }

  function waitAndRegister() {
    if (!document.body || !window.crocbox || !window.crocbox.onConsentRequest) {
      setTimeout(waitAndRegister, 100);
      return;
    }
    window.crocbox.onConsentRequest(function(req) {
      console.log('[CROCbox] Consent request in renderer: holdId=' + req.holdId);
      showConsentCard(req.holdId);
    });
    console.log('[CROCbox] Consent card v2 ready — listening for requests');
    cardReady = true;
  }
  waitAndRegister();
})();
</script>`;
}
// ── HTTP Proxy Handler ─────────────────────────────────────────
function handleHttpRequest(clientReq, clientRes) {
  messageCount.httpRequests++;
  const options = {
    hostname: GATEWAY_HOST,
    port: GATEWAY_PORT,
    path: clientReq.url,
    method: clientReq.method,
    headers: { ...clientReq.headers, host: `${GATEWAY_HOST}:${GATEWAY_PORT}` }
  };
  const proxyReq = http.request(options, (proxyRes) => {
    const contentType = proxyRes.headers['content-type'] || '';
    const isHtml = contentType.includes('text/html');
    if (isHtml) {
      let body = '';
      proxyRes.setEncoding('utf8');
      proxyRes.on('data', (chunk) => { body += chunk; });
      proxyRes.on('end', () => {
        let modified;
        if (body.includes('<head>')) {
          modified = body.replace('<head>', '<head>' + getInjectedScript() + getConsentCardScript());
        } else if (body.includes('<HEAD>')) {
          modified = body.replace('<HEAD>', '<HEAD>' + getInjectedScript() + getConsentCardScript());
        } else {
          modified = getInjectedScript() + getConsentCardScript() + body;
        }
        const headers = { ...proxyRes.headers };
        delete headers['content-length'];
        delete headers['content-encoding'];
        clientRes.writeHead(proxyRes.statusCode, headers);
        clientRes.end(modified);
        console.log(`[ws-proxy] HTTP ${clientReq.url} -> injected auth + WS redirect + consent card`);
      });
    } else {
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes, { end: true });
    }
  });
  proxyReq.on('error', (err) => {
    console.error('[ws-proxy] HTTP proxy error:', err.message);
    clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
    clientRes.end('CROCbox proxy: Gateway unavailable');
  });
  clientReq.pipe(proxyReq, { end: true });
}
// ── Start the Proxy Server ─────────────────────────────────────
function startProxy(config) {
  authToken = config.token;
  deviceId = config.deviceId;
  if (!authToken || !deviceId) {
    return Promise.reject(new Error('startProxy requires token and deviceId'));
  }
  return new Promise((resolve, reject) => {
    const server = http.createServer(handleHttpRequest);
    const wss = new WebSocket.Server({ server });
    wss.on('connection', (clientWs, req) => {
      const connId = crypto.randomUUID().substring(0, 8);
      console.log(`[ws-proxy] Client connected (${connId})`);
      const gatewayWs = new WebSocket(GATEWAY_WS, {
        headers: {
          Origin: `http://${GATEWAY_HOST}:${GATEWAY_PORT}`
        }
      });
      let gatewayReady = false;
      let clientBuffer = [];
      gatewayWs.on('open', () => {
        console.log(`[ws-proxy] Gateway connection opened (${connId})`);
        gatewayReady = true;
        for (const buffered of clientBuffer) {
          gatewayWs.send(buffered.data, { binary: buffered.isBinary });
        }
        clientBuffer = [];
      });
      // ── Client → Gateway (upstream relay) ──────────────────
      clientWs.on('message', (data, isBinary) => {
        messageCount.clientToGateway++;
        let forwardData = data;
        if (!isBinary) {
          try {
            const msg = JSON.parse(data.toString());
            const label = msg.type === 'req' ? `req:${msg.method}` : msg.type;
            console.log(`[ws-proxy] C->G (${connId}): ${label}`);
            // A.8: Rewrite connect request for proxy pass-through
            if (msg.type === 'req' && msg.method === 'connect') {
              msg.params.auth = { token: authToken };
              msg.params.client.id = 'openclaw-macos';
              msg.params.client.mode = 'ui';
              delete msg.params.device;
              forwardData = JSON.stringify(msg);
              console.log(`[ws-proxy] Rewrote connect: openclaw-macos + token auth`);
            }
          } catch (e) {
            console.log(`[ws-proxy] C->G (${connId}): [unparseable]`);
          }
        } else {
          console.log(`[ws-proxy] C->G (${connId}): [binary ${data.length}b]`);
        }
        if (gatewayReady && gatewayWs.readyState === WebSocket.OPEN) {
          gatewayWs.send(forwardData, { binary: isBinary });
        } else {
          clientBuffer.push({ data: forwardData, isBinary });
        }
      });
      // ── Gateway → Client (downstream relay) ────────────────
      //
      // A.10: Intercept exec.approval.requested events (Green Shield).
      // A.10-R: Detect seq-gap in agent event stream (Yellow Shield).
      //
      // Green Shield intercept: exec.approval.requested events are
      // HELD — not forwarded to the Control UI. Currently dead code
      // for openclaw-macos. Preserved for future Green Shield path.
      //
      // Yellow Shield seq-gap detection: Track seq per runId. When
      // an event:agent with stream:'assistant' arrives and seq >
      // lastSeq + 1, a tool executed during the gap. Hold the event,
      // signal consent via IPC. Forward on Allow, drop on Deny/Timeout.
      gatewayWs.on('message', (data, isBinary) => {
        messageCount.gatewayToClient++;
        if (!isBinary) {
          try {
            const msg = JSON.parse(data.toString());
            let label;
            if (msg.type === 'event') {
              label = `event:${msg.event}`;
            } else if (msg.type === 'res') {
              label = `res:${msg.id ? msg.id.substring(0, 12) : '?'}`;
            } else {
              label = msg.type || 'unknown';
            }
            // ── A.10: INTERCEPT exec.approval.requested (Green Shield) ──
            if (msg.type === 'event' && msg.event === 'exec.approval.requested') {
              const approval = msg.payload;
              if (approval && approval.id) {
                pendingApprovals.set(approval.id, {
                  id: approval.id,
                  request: approval.request || {},
                  createdAtMs: approval.createdAtMs || Date.now(),
                  expiresAtMs: approval.expiresAtMs || (Date.now() + 60000),
                  connId: connId,
                  gatewayWs: gatewayWs
                });
                console.log(`[ws-proxy] *** A.10 INTERCEPTED *** exec.approval.requested (${connId})`);
                console.log(`[ws-proxy]   Approval ID: ${approval.id}`);
                console.log(`[ws-proxy]   Command: ${approval.request?.command || 'unknown'}`);
                console.log(`[ws-proxy]   CWD: ${approval.request?.cwd || 'n/a'}`);
                console.log(`[ws-proxy]   Expires: ${new Date(approval.expiresAtMs || 0).toISOString()}`);
                console.log(`[ws-proxy]   HELD — not forwarded to Control UI`);
                return;
              }
            }
            // ── A.10: Also intercept resolved events (Green Shield) ──
            if (msg.type === 'event' && msg.event === 'exec.approval.resolved') {
              console.log(`[ws-proxy] G->C (${connId}): ${label} (intercepted — not forwarded)`);
              return;
            }
            // ── A.10-R: YELLOW SHIELD — Seq-Gap Detection ───────────
            if (msg.type === 'event' && msg.event === 'agent') {
              const payload = msg.payload || {};
              const runId = payload.runId;
              const seq = payload.seq;
              const stream = payload.stream;
              if (runId && typeof seq === 'number') {
                // Get or create run tracking state
                if (!runState.has(runId)) {
                  runState.set(runId, { lastSeq: 0, state: 'streaming', holdId: null });
                }
                const run = runState.get(runId);
                // If we are holding events for this run, buffer this one too
                if (run.state === 'holding' && run.holdId) {
                  const held = heldEvents.get(run.holdId);
                  if (held && held.state === 'pending') {
                    held.events.push({ data, isBinary });
                    run.lastSeq = seq;
                    console.log(`[ws-proxy] G->C (${connId}): ${label} seq=${seq} stream=${stream} [BUFFERED holdId=${run.holdId}]`);
                    return;
                  }
                }
                // If run was denied, drop all further events for this run
                if (run.state === 'denied') {
                  run.lastSeq = seq;
                  console.log(`[ws-proxy] G->C (${connId}): ${label} seq=${seq} stream=${stream} [DROPPED — denied]`);
                  return;
                }
                // Seq-gap detection on assistant stream
                if (stream === 'assistant' && run.lastSeq > 0 && seq > run.lastSeq + 1) {
                  // *** SEQ GAP DETECTED — Yellow Shield trigger ***
                  const gapSize = seq - run.lastSeq - 1;
                  const holdId = 'ysh-' + crypto.randomUUID().substring(0, 12);
                  console.log(`[ws-proxy] *** SEQ GAP DETECTED *** runId=${runId} lastSeq=${run.lastSeq} thisSeq=${seq} gap=${gapSize}`);
                  console.log(`[ws-proxy]   Yellow Shield: tool executed during seqs ${run.lastSeq + 1}-${seq - 1}`);
                  console.log(`[ws-proxy]   Holding first assistant event (holdId=${holdId})`);
                  console.log(`[ws-proxy]   Waiting for consent decision...`);
                  // Update run state to holding
                  run.state = 'holding';
                  run.holdId = holdId;
                  run.lastSeq = seq;
                  // Buffer this event
                  heldEvents.set(holdId, {
                    runId: runId,
                    events: [{ data, isBinary }],
                    gapSize: gapSize,
                    detectedAt: Date.now(),
                    clientWs: clientWs,
                    connId: connId,
                    state: 'pending'
                  });
                  // Signal Electron main process via IPC
                  var consentRequest = {
                    holdId: holdId,
                    runId: runId,
                    gapSize: gapSize,
                    heldEventCount: 1,
                    detectedAt: Date.now()
                  };
                  if (consentIPCCallback) {
                    consentIPCCallback(consentRequest);
                    console.log(`[ws-proxy]   IPC consent signal sent (holdId=${holdId})`);
                  } else {
                    console.log(`[ws-proxy]   WARNING: No IPC callback registered`);
                    console.log(`[ws-proxy]   Fail-closed: treating as timeout`);
                    setTimeout(function() {
                      resolveConsent(holdId, 'timeout');
                    }, 100);
                  }
                  // Start consent timeout timer
                  (function(hid) {
                    setTimeout(function() {
                      var h = heldEvents.get(hid);
                      if (h && h.state === 'pending') {
                        console.log(`[ws-proxy] *** CONSENT TIMEOUT *** holdId=${hid} (${CONSENT_TIMEOUT_MS}ms elapsed)`);
                        resolveConsent(hid, 'timeout');
                      }
                    }, CONSENT_TIMEOUT_MS);
                  })(holdId);
                  return;
                }
                // Lifecycle and normal events: track seq, forward
                run.lastSeq = seq;
                console.log(`[ws-proxy] G->C (${connId}): ${label} seq=${seq} stream=${stream || 'n/a'}`);
              } else {
                console.log(`[ws-proxy] G->C (${connId}): ${label} (no seq tracking)`);
              }
            } else {
              // Non-agent events — forward normally
              console.log(`[ws-proxy] G->C (${connId}): ${label}`);
            }
          } catch (e) {
            console.log(`[ws-proxy] G->C (${connId}): [unparseable]`);
          }
        } else {
          console.log(`[ws-proxy] G->C (${connId}): [binary ${data.length}b]`);
        }
        // ── Forward to client (default path) ──
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(data, { binary: isBinary });
        }
      });
      // ── Error and close handling ───────────────────────────
      clientWs.on('close', (code) => {
        console.log(`[ws-proxy] Client disconnected (${connId}): ${code}`);
        if (gatewayWs.readyState === WebSocket.OPEN ||
            gatewayWs.readyState === WebSocket.CONNECTING) {
          gatewayWs.close();
        }
      });
      clientWs.on('error', (err) => {
        console.error(`[ws-proxy] Client error (${connId}):`, err.message);
        if (gatewayWs.readyState === WebSocket.OPEN) {
          gatewayWs.close();
        }
      });
      gatewayWs.on('close', (code) => {
        console.log(`[ws-proxy] Gateway disconnected (${connId}): ${code}`);
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close();
        }
      });
      gatewayWs.on('error', (err) => {
        console.error(`[ws-proxy] Gateway error (${connId}):`, err.message);
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close();
        }
      });
    });
    // ── Start listening ──────────────────────────────────────
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`[ws-proxy] FATAL: Port ${PROXY_PORT} already in use`);
        reject(new Error(`Proxy port ${PROXY_PORT} in use`));
      } else {
        console.error('[ws-proxy] Server error:', err.message);
        reject(err);
      }
    });
    server.listen(PROXY_PORT, GATEWAY_HOST, () => {
      console.log(`[ws-proxy] Listening on http+ws://${GATEWAY_HOST}:${PROXY_PORT}`);
      console.log(`[ws-proxy] Relaying to http+ws://${GATEWAY_HOST}:${GATEWAY_PORT}`);
      console.log(`[ws-proxy] Yellow Shield: seq-gap detection ACTIVE (timeout=${CONSENT_TIMEOUT_MS}ms)`);
      resolve(server);
    });
  });
}
// ── Stop the Proxy Server ──────────────────────────────────────
function stopProxy(server) {
  return new Promise((resolve) => {
    if (!server) {
      resolve();
      return;
    }
    for (const [holdId, held] of heldEvents) {
      if (held.state === 'pending') {
        console.log(`[ws-proxy] Shutdown: resolving pending hold ${holdId} as timeout`);
        resolveConsent(holdId, 'timeout');
      }
    }
    heldEvents.clear();
    runState.clear();
    server.close(() => {
      console.log('[ws-proxy] Proxy server stopped');
      resolve();
    });
  });
}
// ── Exports ────────────────────────────────────────────────────
module.exports = {
  startProxy,
  stopProxy,
  setConsentIPC,
  resolveConsent,
  PROXY_PORT,
  pendingApprovals,
  heldEvents,
  runState
};
