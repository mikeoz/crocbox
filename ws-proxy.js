/**
 * CROCbox — WebSocket MITM Proxy (ws-proxy.js)
 * OTN-Connected (v3) — Yellow Shield retired, August 15, 2026
 * 
 * Launch Checklist A.7 + A.8:
 *   A.7: Auth token auto-injected (no manual paste)
 *   A.8: WebSocket MITM proxy relays all messages transparently
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
 */
'use strict';
// Guard against EPIPE crashes when stdout pipe is closed (e.g., | head)
process.stdout.on('error', (err) => { if (err.code === 'EPIPE') process.exit(0); });
process.stderr.on('error', (err) => { if (err.code === 'EPIPE') process.exit(0); });

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
let proxyScenario = 'NHB';
let deviceId = null;

let greenShieldActive = false;
function setGreenShieldActive(active) {
  greenShieldActive = !!active;
  console.log('[ws-proxy] Green Shield active: ' + greenShieldActive);
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
  // Hide OpenClaw update banner by text content
  setTimeout(function() {
    var allDivs = document.querySelectorAll('div');
    for (var i = 0; i < allDivs.length; i++) {
      if (allDivs[i].textContent.includes('Update available') && allDivs[i].textContent.includes('Update now')) {
        allDivs[i].style.display = 'none';
        console.log('[CROCbox] Update banner hidden');
        break;
      }
    }
  }, 2000);
  // Re-check periodically in case SPA re-renders it
  setInterval(function() {
    var allDivs = document.querySelectorAll('div');
    for (var i = 0; i < allDivs.length; i++) {
      if (allDivs[i].textContent.includes('Update available') && allDivs[i].textContent.includes('Update now')) {
        allDivs[i].style.display = 'none';
        break;
      }
    }
  }, 5000);
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
          modified = body.replace('<head>', '<head><style id="crocbox-hide-update">' +
          '/* Hide OpenClaw update banner — CROCbox pins its own version */' +
          '/* B3: Reserve space for Trust Bar at top of viewport */' +
          'body { margin-top: 40px !important; }' +
          '/* B2: Target only the update banner, not all elements with update in class */' +
          '#crocbox-trust-bar ~ div[style*="background-color: rgb(254"], #crocbox-trust-bar ~ div[style*="background-color: red"] { display:none !important; }' +
          '</style>' + getInjectedScript());
        } else if (body.includes('<HEAD>')) {
          modified = body.replace('<HEAD>', '<HEAD>' + getInjectedScript());
        } else {
          modified = getInjectedScript() + body;
        }
        const headers = { ...proxyRes.headers };
        delete headers['content-length'];
        delete headers['content-encoding'];
        clientRes.writeHead(proxyRes.statusCode, headers);
        clientRes.end(modified);
        console.log(`[ws-proxy] HTTP ${clientReq.url} -> injected auth + WS redirect`);
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
  proxyScenario = config.scenario || 'NHB';
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
              if (proxyScenario === 'EXISTING_OC') {
                // Existing user: pass through the Control UI's native connect request.
                // The #token= fragment gives the UI operator-level credentials.
                // Inject token into auth but preserve client type and device identity.
                if (!msg.params.auth || !msg.params.auth.token) {
                  msg.params.auth = { token: authToken };
                }
                forwardData = JSON.stringify(msg);
                console.log(`[ws-proxy] EXISTING_OC: pass-through connect (client=${msg.params.client.id})`);
              } else {
                msg.params.auth = { token: authToken };
                msg.params.client.id = 'openclaw-macos';
                msg.params.client.mode = 'ui';
                delete msg.params.device;
                forwardData = JSON.stringify(msg);
                console.log(`[ws-proxy] Rewrote connect: openclaw-macos + token auth`);
              }
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
      // Green Shield intercept: exec.approval.requested events are
      // HELD — not forwarded to the Control UI. Currently dead code
      // for openclaw-macos. Preserved for future Green Shield path.
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
            // ── Agent events: log and forward ──
            if (msg.type === 'event' && msg.event === 'agent') {
              const payload = msg.payload || {};
              const seq = payload.seq;
              const stream = payload.stream;
              if (typeof seq === 'number') {
                console.log(`[ws-proxy] G->C (${connId}): ${label} seq=${seq} stream=${stream || 'n/a'}`);
              } else {
                console.log(`[ws-proxy] G->C (${connId}): ${label} (no seq tracking)`);
              }
            } else {
              // Non-agent events — log
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
    server.close(() => {
      console.log('[ws-proxy] Proxy server stopped');
      resolve();
    });
  });
}
// ── Exports ────────────────────────────────────────────────────
module.exports = {
  setGreenShieldActive,
  startProxy,
  stopProxy,
  PROXY_PORT,
  pendingApprovals
};
