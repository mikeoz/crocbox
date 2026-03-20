/**
 * CROCbox v0.8 — Electron Main Process
 * 
 * Phase 1: Gateway Connection
 * Phase 2: BrowserWindow + Control UI
 * A.7: Auth token auto-injected via proxy HTML injection
 * A.8: WebSocket MITM proxy with HTTP proxying and WS redirect
 * A.11: Yellow Shield consent IPC bridge (proxy <-> renderer)
 * 
 * Architecture:
 *   Electron Main Process
 *     |- Gateway health check (is OpenClaw running?)
 *     |- WebSocket connection (openclaw-macos, token auth)
 *     |- ws-proxy.js (port 18788 -> HTTP+WS relay to Gateway 18789)
 *     |     -> Injects auth token into HTML localStorage (A.7)
 *     |     -> Injects WebSocket redirect into HTML (A.8)
 *     |     -> Seq-gap detection + consent hold (A.10-R)
 *     |- BrowserWindow loads http://127.0.0.1:18788 (proxy)
 *     +-- IPC bridge: proxy consent signals <-> renderer consent card (A.11)
 * 
 * @see OPN_ENG_A10-YellowShield_18MAR26_v1 — Yellow Shield architecture
 * @see OPN_ENG_v08-Architecture_15MAR26_v1, Section 3.2
 * @see OPN_PM_FullCROC-Mode_16MAR26_v2, Section 5
 */
const { app, BrowserWindow, ipcMain } = require('electron');
const { execSync } = require('child_process');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
// ── MITM Proxy Module ──────────────────────────────────────────
const { startProxy, stopProxy, setConsentIPC, resolveConsent, PROXY_PORT } = require('./ws-proxy');
// ── Configuration ──────────────────────────────────────────────
const GATEWAY_PORT = 18789;
const GATEWAY_HOST = '127.0.0.1';
const GATEWAY_URL = `http://${GATEWAY_HOST}:${GATEWAY_PORT}`;
const GATEWAY_WS = `ws://${GATEWAY_HOST}:${GATEWAY_PORT}`;
const PROXY_URL = `http://${GATEWAY_HOST}:${PROXY_PORT}`;
// ── Read OpenClaw config for auth token ────────────────────────
function readGatewayToken() {
  const configPath = path.join(
    process.env.HOME || '/tmp',
    '.openclaw',
    'openclaw.json'
  );
  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    return config.gateway?.auth?.token || null;
  } catch (err) {
    console.error('[CROCbox] Could not read openclaw.json:', err.message);
    return null;
  }
}
// ── Generate stable deviceId ───────────────────────────────────
function getCROCboxDeviceId() {
  const username = process.env.USER || 'unknown';
  const hostname = require('os').hostname();
  const raw = `crocbox-${username}-${hostname}`;
  return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
}
// ── Check if Gateway is running ────────────────────────────────
function checkGatewayRunning() {
  return new Promise((resolve) => {
    const http = require('http');
    const req = http.get(
      { host: GATEWAY_HOST, port: GATEWAY_PORT, path: '/', timeout: 3000 },
      (res) => {
        res.resume();
        resolve(true);
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}
// ── Connect to Gateway WebSocket ───────────────────────────────
function connectToGateway(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(GATEWAY_WS, {
      headers: { Origin: GATEWAY_URL }
    });
    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error('Gateway WebSocket connection timed out'));
    }, 10000);
    ws.on('open', () => {
      console.log('[CROCbox] WebSocket connected to Gateway');
    });
    ws.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); }
      catch { return; }
      if (msg.type === 'event' && msg.event === 'connect.challenge') {
        console.log('[CROCbox] Received challenge nonce, sending connect...');
        const connectMsg = {
          type: 'req',
          id: 'crocbox-connect-001',
          method: 'connect',
          params: {
            minProtocol: 3,
            maxProtocol: 3,
            client: {
              id: 'openclaw-macos',
              version: '0.8.0',
              platform: 'darwin',
              mode: 'ui',
              instanceId: 'crocbox-' + Date.now()
            },
            role: 'operator',
            scopes: ['operator.admin', 'operator.approvals', 'operator.pairing'],
            auth: { token: token },
            userAgent: 'CROCbox/0.8.0',
            locale: 'en-US'
          }
        };
        ws.send(JSON.stringify(connectMsg));
      }
      if (msg.type === 'res' && msg.id === 'crocbox-connect-001') {
        clearTimeout(timeout);
        if (msg.ok) {
          console.log('[CROCbox] Gateway hello-ok received');
          console.log('[CROCbox]   Server:', msg.payload.server?.version);
          console.log('[CROCbox]   ConnID:', msg.payload.server?.connId);
          console.log('[CROCbox]   Protocol:', msg.payload.protocol);
          resolve({ ws, hello: msg.payload });
        } else {
          ws.close();
          reject(new Error('Gateway connect failed: ' + (msg.error?.message || 'unknown')));
        }
      }
    });
    ws.on('error', (err) => {
      clearTimeout(timeout);
      reject(new Error('Gateway WebSocket error: ' + err.message));
    });
    ws.on('close', () => {
      console.log('[CROCbox] Gateway WebSocket closed');
    });
  });
}
// ── Create the main application window ─────────────────────────
function createWindow(gatewayConnection) {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    title: 'CROCbox',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 15, y: 12 },
    backgroundColor: '#0a0a0a',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });
  console.log('[CROCbox] Loading Control UI from ' + PROXY_URL + ' (via proxy)');
  win.loadURL(PROXY_URL);
  win.webContents.on('did-finish-load', () => {
    console.log('[CROCbox] Control UI loaded in BrowserWindow');
    // A.11 DEBUG: Forward renderer console to Terminal
    win.webContents.on('console-message', function(_ev, level, msg) {
      if (msg.includes('CROCbox')) console.log('[renderer] ' + msg);
    });
    win.webContents.executeJavaScript(`
      document.title = 'CROCbox — Your AI, Your Control';
    `).catch(() => {});
  });
  win.on('closed', () => {
    if (gatewayConnection && gatewayConnection.ws) {
      gatewayConnection.ws.close();
    }
  });
  return win;
}
// ── A.11: Wire Yellow Shield Consent IPC ───────────────────────
//
// The proxy detects a seq-gap (tool execution) and calls the IPC
// callback. main.js forwards the consent request to the renderer
// via webContents.send. The renderer shows the consent card and
// sends the decision back via ipcMain.handle.
//
// Flow:
//   ws-proxy.js (gap detected)
//     -> consentIPCCallback(request)
//       -> main.js sends 'crocbox:consent-request' to renderer
//         -> renderer shows Yellow Shield consent card
//           -> user clicks Allow/Deny
//             -> renderer calls ipcRenderer.invoke('crocbox:consent-resolve')
//               -> main.js calls resolveConsent(holdId, decision)
//                 -> ws-proxy.js forwards or drops held events
function wireConsentIPC(win) {
  // Register the IPC callback with the proxy
  setConsentIPC(function(consentRequest) {
    if (!win || win.isDestroyed() || !win.webContents) {
      console.log('[CROCbox] IPC: Window not available — consent will timeout (fail-closed)');
      return;
    }
    console.log('[CROCbox] IPC: Showing consent card via executeJavaScript (holdId=' + consentRequest.holdId + ')');
    // Also send via IPC for preload bridge
    win.webContents.send('crocbox:consent-request', consentRequest);
    // Inject consent card directly into the page via executeJavaScript
    var cardJS = `
      (function() {
        var holdId = '${consentRequest.holdId}';
        // Remove any existing card
        var old = document.getElementById('crocbox-consent-overlay');
        if (old) old.remove();
        // Add style if needed
        if (!document.getElementById('crocbox-consent-style')) {
          var s = document.createElement('style');
          s.id = 'crocbox-consent-style';
          s.textContent = '#crocbox-consent-overlay { position:fixed; top:0; right:0; bottom:0; width:360px; z-index:999999; background:rgba(0,0,0,0.92); border-left:3px solid #d4a017; font-family:-apple-system,BlinkMacSystemFont,sans-serif; color:#f0f0f0; display:flex; flex-direction:column; } #crocbox-consent-overlay button { flex:1; padding:14px 16px; border:none; border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; } #crocbox-btn-allow { background:#d4a017; color:#000; } #crocbox-btn-deny { background:#333; color:#f0f0f0; border:1px solid #555; }';
          document.head.appendChild(s);
        }
        var overlay = document.createElement('div');
        overlay.id = 'crocbox-consent-overlay';
        overlay.innerHTML = '<div style="padding:24px 24px 16px; border-bottom:1px solid rgba(212,160,23,0.3)"><div style="font-size:48px; margin-bottom:8px">\\uD83D\\uDEE1\\uFE0F</div><div style="font-size:17px; font-weight:600; color:#d4a017; margin-bottom:6px">Yellow Shield</div><div style="font-size:13px; color:#999">Action Detected</div></div><div style="flex:1; padding:20px 24px"><div style="font-size:14px; color:#ccc; line-height:1.6; margin-bottom:16px">Your AI executed an action. The result is ready but has <strong>not been delivered</strong> yet.<br><br><strong>You decide what happens next.</strong></div><div style="background:rgba(212,160,23,0.1); border:1px solid rgba(212,160,23,0.25); border-radius:8px; padding:12px; font-size:12px; color:#b0b0b0; line-height:1.5">Yellow Shield means the action already ran. CROCbox controls whether the result reaches you.</div></div><div style="padding:16px 24px 24px; display:flex; gap:12px"><button id="crocbox-btn-allow">Allow Result</button><button id="crocbox-btn-deny">Block Result</button></div>';
        document.body.appendChild(overlay);
        console.log('[CROCbox] Consent card injected via executeJavaScript');
        document.getElementById('crocbox-btn-allow').addEventListener('click', function() {
          console.log('[CROCbox] User clicked ALLOW');
          overlay.remove();
          if (window.crocbox && window.crocbox.resolveConsent) {
            window.crocbox.resolveConsent(holdId, 'allow');
          }
        });
        document.getElementById('crocbox-btn-deny').addEventListener('click', function() {
          console.log('[CROCbox] User clicked DENY');
          overlay.remove();
          if (window.crocbox && window.crocbox.resolveConsent) {
            window.crocbox.resolveConsent(holdId, 'deny');
          }
        });
      })();
    `;
    win.webContents.executeJavaScript(cardJS).then(function() {
      console.log('[CROCbox] IPC: Consent card executeJavaScript succeeded');
    }).catch(function(err) {
      console.log('[CROCbox] IPC: Consent card executeJavaScript failed: ' + err.message);
    });
  });
  // Handle consent decisions from the renderer
  ipcMain.handle('crocbox:consent-resolve', function(_event, holdId, decision) {
    console.log('[CROCbox] IPC: Received consent decision from renderer: holdId=' + holdId + ' decision=' + decision);
    // Validate decision
    if (decision !== 'allow' && decision !== 'deny') {
      console.log('[CROCbox] IPC: Invalid decision "' + decision + '" — treating as deny');
      decision = 'deny';
    }
    var result = resolveConsent(holdId, decision);
    return { success: result, holdId: holdId, decision: decision };
  });
  console.log('[CROCbox] Yellow Shield consent IPC wired ✓');
}
// ── Application lifecycle ──────────────────────────────────────
let mainWindow = null;
let gatewayConnection = null;
let gatewayToken = null;
let proxyServer = null;
app.whenReady().then(async () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   CROCbox v0.8.0 — Soft Launch       ║');
  console.log('  ║   The Agent Trust Layer for OpenClaw  ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
  // Step 1: Read auth token
  gatewayToken = readGatewayToken();
  if (!gatewayToken) {
    console.error('[CROCbox] FATAL: No Gateway auth token found in ~/.openclaw/openclaw.json');
    console.error('[CROCbox] Run "openclaw" first to set up OpenClaw.');
    app.quit();
    return;
  }
  console.log('[CROCbox] Auth token loaded from openclaw.json');
  // Step 2: Check Gateway is running
  console.log('[CROCbox] Checking Gateway at ' + GATEWAY_URL + '...');
  var running = await checkGatewayRunning();
  if (!running) {
    console.error('[CROCbox] FATAL: OpenClaw Gateway not running on port ' + GATEWAY_PORT);
    console.error('[CROCbox] Start it with: openclaw');
    app.quit();
    return;
  }
  console.log('[CROCbox] Gateway is running ✓');
  // Step 3: Connect via WebSocket (CROCbox main process connection)
  try {
    gatewayConnection = await connectToGateway(gatewayToken);
    console.log('[CROCbox] Gateway connection established ✓');
  } catch (err) {
    console.error('[CROCbox] FATAL: ' + err.message);
    app.quit();
    return;
  }
  // Step 4: Start the HTTP+WS Proxy (A.7 + A.8 + A.10-R)
  var deviceId = getCROCboxDeviceId();
  try {
    proxyServer = await startProxy({ token: gatewayToken, deviceId: deviceId });
    console.log('[CROCbox] HTTP+WS proxy started ✓');
    console.log('[CROCbox] DeviceId: ' + deviceId);
  } catch (err) {
    console.error('[CROCbox] FATAL: Could not start proxy — ' + err.message);
    app.quit();
    return;
  }
  // Step 5: Create the application window
  mainWindow = createWindow(gatewayConnection);
  console.log('[CROCbox] Application window created ✓');
  // Step 6: Wire Yellow Shield consent IPC (A.11)
  wireConsentIPC(mainWindow);
  console.log('');
});
app.on('window-all-closed', async () => {
  if (gatewayConnection && gatewayConnection.ws) {
    gatewayConnection.ws.close();
  }
  if (proxyServer) {
    await stopProxy(proxyServer);
  }
  app.quit();
});
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0 && gatewayConnection) {
    mainWindow = createWindow(gatewayConnection);
  }
});
