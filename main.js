/**
 * CROCbox v0.9 — Electron Main Process
 * 
 * Phase 1: Gateway Connection (with auto-start + native error dialogs)
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
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { execSync } = require('child_process');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
// ── MITM Proxy Module ──────────────────────────────────────────
const { startProxy, stopProxy, setConsentIPC, resolveConsent, PROXY_PORT } = require('./ws-proxy');
const { computeShieldScore, getShieldDetailHTML, parseCatalog } = require('./shield-score');
const { enroll: veEnroll, verify: veVerify, checkStatus: veCheckStatus } = require('./card_ve_client');
// ── Configuration ──────────────────────────────────────────────
const GATEWAY_PORT = 18789;
const GATEWAY_HOST = '127.0.0.1';
const GATEWAY_URL = `http://${GATEWAY_HOST}:${GATEWAY_PORT}`;
const GATEWAY_WS = `ws://${GATEWAY_HOST}:${GATEWAY_PORT}`;
const PROXY_URL = `http://${GATEWAY_HOST}:${PROXY_PORT}`;

// ── CROCbox state directory ────────────────────────────────────
const CROCBOX_STATE_DIR = path.join(process.env.HOME || '/tmp', '.crocbox');
function ensureStateDir() {
  if (!fs.existsSync(CROCBOX_STATE_DIR)) {
    fs.mkdirSync(CROCBOX_STATE_DIR, { recursive: true });
    console.log('[CROCbox] Created state directory: ' + CROCBOX_STATE_DIR);
  }
}
function isFirstLaunch() {
  return !fs.existsSync(path.join(CROCBOX_STATE_DIR, 'launched'));
}
function markLaunched() {
  ensureStateDir();
  fs.writeFileSync(
    path.join(CROCBOX_STATE_DIR, 'launched'),
    JSON.stringify({ firstLaunch: new Date().toISOString(), version: '0.9.0' }),
    'utf8'
  );
}
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
// ── Detect if OpenClaw is installed ────────────────────────────
function detectOpenClaw() {
  try {
    const result = require('child_process').execSync('which openclaw 2>/dev/null', { encoding: 'utf8' }).trim();
    if (result) {
      console.log('[CROCbox] OpenClaw found at: ' + result);
      return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}
// ── Auto-start Gateway if not running ──────────────────────────
function autoStartGateway() {
  return new Promise((resolve) => {
    console.log('[CROCbox] Attempting to auto-start Gateway...');
    try {
      // Start gateway in background
      const { spawn } = require('child_process');
      const gw = spawn('openclaw', ['gateway', '--port', String(GATEWAY_PORT)], {
        stdio: 'ignore',
        detached: true,
        env: Object.assign({}, process.env, { PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || '') })
      });
      gw.unref();
      // Poll for gateway to become available (up to 15 seconds)
      let attempts = 0;
      const maxAttempts = 30; // 30 x 500ms = 15 seconds
      const poll = setInterval(async () => {
        attempts++;
        const running = await checkGatewayRunning();
        if (running) {
          clearInterval(poll);
          console.log('[CROCbox] Gateway auto-started successfully (' + (attempts * 0.5) + 's)');
          resolve(true);
        } else if (attempts >= maxAttempts) {
          clearInterval(poll);
          console.log('[CROCbox] Gateway did not start within 15 seconds');
          resolve(false);
        }
      }, 500);
    } catch (err) {
      console.error('[CROCbox] Auto-start failed: ' + err.message);
      resolve(false);
    }
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
// ── Trust Network Indicator ─────────────────────────────────────
function injectTrustNetworkIndicator(win, status) {
  if (!win || win.isDestroyed()) return;
  var color = status === 'enrolled' ? '#4CAF50' : status === 'local' ? '#d4a017' : '#888';
  var label = status === 'enrolled' ? 'Trust Network' : status === 'local' ? 'Local Mode' : 'Not Connected';
  var dot = status === 'enrolled' ? '\u2705' : status === 'local' ? '\uD83D\uDFE1' : '\u26AA';

  win.webContents.executeJavaScript(`
    (function() {
      var old = document.getElementById('crocbox-trust-indicator');
      if (old) old.remove();
      var el = document.createElement('div');
      el.id = 'crocbox-trust-indicator';
      el.style.cssText = 'position:fixed;top:8px;right:180px;z-index:999989;padding:3px 10px;border-radius:6px;background:rgba(0,0,0,0.6);border:1px solid ${color}40;display:flex;align-items:center;gap:5px;font-family:-apple-system,sans-serif;font-size:10px;color:${color};';
      el.innerHTML = '<span>${dot}</span><span>${label}</span>';
      document.body.appendChild(el);
      console.log('[CROCbox] Trust Network indicator: ${status}');
    })();
  `).catch(function() {});
}

// ── VE Startup Check ───────────────────────────────────────────
async function checkVeEnrollment() {
  try {
    var result = await veCheckStatus();
    if (result.status === 'active') {
      veStatus = 'enrolled';
      veAgentId = result.agent_id;
      console.log('[CROCbox] VE: Agent enrolled and active (id=' + result.agent_id + ')');
      return 'enrolled';
    } else if (result.status === 'not_enrolled') {
      console.log('[CROCbox] VE: Agent not enrolled — running in local mode');
      veStatus = 'local';
      return 'local';
    } else {
      console.log('[CROCbox] VE: Status check returned: ' + result.status + ' — ' + (result.reason || ''));
      veStatus = 'local';
      return 'local';
    }
  } catch (err) {
    console.log('[CROCbox] VE: Status check failed — ' + err.message + ' — running in local mode');
    veStatus = 'local';
    return 'local';
  }
}

// ── Shield Scoring Engine UI ────────────────────────────────────
function injectShieldIcon(win, score) {
  if (!win || win.isDestroyed()) return;
  const colorHex = score.color === 'green' ? '#4CAF50' :
                   score.color === 'yellow' ? '#d4a017' : '#e53935';
  const shieldChar = score.color === 'green' ? '\u2705' :
                     score.color === 'yellow' ? '\uD83D\uDEE1\uFE0F' : '\uD83D\uDD34';

  win.webContents.executeJavaScript(`
    (function() {
      // Remove existing shield
      var old = document.getElementById('crocbox-shield-icon');
      if (old) old.remove();
      if (!document.getElementById('crocbox-shield-style')) {
        var s = document.createElement('style');
        s.id = 'crocbox-shield-style';
        s.textContent = '#crocbox-shield-icon { position:fixed; top:8px; right:12px; z-index:999990; cursor:pointer; padding:4px 12px; border-radius:8px; background:rgba(0,0,0,0.7); border:1px solid ${colorHex}40; display:flex; align-items:center; gap:6px; transition:all 0.2s; } #crocbox-shield-icon:hover { background:rgba(0,0,0,0.9); border-color:${colorHex}; } #crocbox-shield-detail { position:fixed; top:44px; right:12px; z-index:999991; width:340px; background:rgba(0,0,0,0.95); border:1px solid ${colorHex}40; border-radius:12px; display:none; } #crocbox-shield-detail.visible { display:block; }';
        document.head.appendChild(s);
      }
      var icon = document.createElement('div');
      icon.id = 'crocbox-shield-icon';
      icon.innerHTML = '<span style="font-size:18px">${shieldChar}</span><span style="font-size:11px;color:${colorHex};font-weight:600;font-family:-apple-system,sans-serif;text-transform:uppercase">${score.color} Shield</span>';
      document.body.appendChild(icon);
      // Detail panel
      var detail = document.createElement('div');
      detail.id = 'crocbox-shield-detail';
      document.body.appendChild(detail);
      icon.addEventListener('click', function() {
        if (detail.classList.contains('visible')) {
          detail.classList.remove('visible');
        } else {
          // Request detail HTML from main process
          if (window.crocbox && window.crocbox.getShieldDetail) {
            window.crocbox.getShieldDetail().then(function(html) {
              detail.innerHTML = html + '<div style="padding:0 20px 16px;text-align:center"><button style="background:none;border:1px solid #555;color:#888;padding:6px 16px;border-radius:6px;cursor:pointer;font-size:11px" onclick="document.getElementById(\\'crocbox-shield-detail\\').classList.remove(\\'visible\\')">Close</button></div>';
              detail.classList.add('visible');
            });
          }
        }
      });
      console.log('[CROCbox] Shield icon injected: ${score.color}');
    })();
  `).catch(function(err) {
    console.log('[CROCbox] Shield icon injection failed: ' + err.message);
  });
}

function computeAndInjectShield(win, catalogPayload) {
  var tools = parseCatalog(catalogPayload);
  if (tools.length === 0) {
    console.log('[CROCbox] Shield: No tools in catalog — skipping');
    return;
  }
  // Current CROCbox is always Yellow Shield (CBD)
  currentShieldScore = computeShieldScore(tools, 'yellow', 0);
  console.log('[CROCbox] Shield Score computed:');
  console.log('[CROCbox]   Color: ' + currentShieldScore.color.toUpperCase());
  console.log('[CROCbox]   OWASP: ' + currentShieldScore.owasp.classified + '/' + currentShieldScore.owasp.toolCount + ' classified');
  console.log('[CROCbox]   AWS Scope: ' + currentShieldScore.aws.scope + ' (' + currentShieldScore.aws.label + ')');
  console.log('[CROCbox]   Meta: ' + currentShieldScore.meta.config + (currentShieldScore.meta.hitlRequired ? ' — HITL mandatory' : ''));
  console.log('[CROCbox]   Catalog Hash: ' + currentShieldScore.catalogHash.substring(0, 16) + '...');
  injectShieldIcon(win, currentShieldScore);
}

// ── Welcome Screen (first launch only) ─────────────────────────
function showWelcomeScreen() {
  return new Promise((resolve) => {
    const welcomeWin = new BrowserWindow({
      width: 640,
      height: 620,
      resizable: false,
      minimizable: false,
      maximizable: false,
      title: 'Welcome to CROCbox',
      titleBarStyle: 'hiddenInset',
      trafficLightPosition: { x: 15, y: 12 },
      backgroundColor: '#0a0a0a',
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true
      }
    });
    const welcomeHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0a0a; color:#f0f0f0; font-family:-apple-system,BlinkMacSystemFont,sans-serif;
         display:flex; flex-direction:column; height:100vh; -webkit-app-region:drag; user-select:none; }
  .content { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:40px; }
  .shield { font-size:72px; margin-bottom:16px; }
  h1 { font-size:28px; font-weight:700; margin-bottom:8px; color:#f0f0f0; }
  .subtitle { font-size:15px; color:#999; margin-bottom:32px; }
  .steps { text-align:left; width:100%; max-width:420px; }
  .step { display:flex; align-items:flex-start; gap:14px; margin-bottom:20px; }
  .step-num { width:28px; height:28px; border-radius:50%; background:#d4a017; color:#000;
              display:flex; align-items:center; justify-content:center; font-weight:700;
              font-size:14px; flex-shrink:0; }
  .step-text { font-size:14px; line-height:1.5; color:#ccc; padding-top:3px; }
  .step-text strong { color:#f0f0f0; }
  .btn-row { padding:24px 40px; display:flex; justify-content:center; -webkit-app-region:no-drag; }
  .btn { padding:14px 48px; border:none; border-radius:10px; font-size:16px; font-weight:600;
         cursor:pointer; background:#d4a017; color:#000; }
  .btn:hover { background:#e0b020; }
  .footer { font-size:11px; color:#555; text-align:center; padding-bottom:16px; }
</style></head><body>
<div class="content">
  <div class="shield">\u{1F6E1}\u{FE0F}</div>
  <h1>Your AI, Your Control</h1>
  <div class="subtitle">CROCbox wraps your AI agent in a trust layer</div>
  <div class="steps">
    <div class="step"><div class="step-num">1</div>
      <div class="step-text"><strong>Your AI acts.</strong> It can search the web, run commands, read files \u2014 real actions on your computer.</div></div>
    <div class="step"><div class="step-num">2</div>
      <div class="step-text"><strong>CROCbox catches it.</strong> Every action is detected and held. The Yellow Shield appears.</div></div>
    <div class="step"><div class="step-num">3</div>
      <div class="step-text"><strong>You decide.</strong> Allow the result or block it. Your choice, every time.</div></div>
  </div>
</div>
<div class="btn-row"><button class="btn" onclick="window.close()">See the Magic</button></div>
<div class="footer">My data + Your AI + My control = Living Intelligence</div>
</body></html>`;
    welcomeWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(welcomeHTML));
    welcomeWin.on('closed', () => {
      resolve();
    });
  });
}
// ── Inject pre-loaded first prompt ─────────────────────────────
function injectFirstPrompt(win) {
  // Wait for the OpenClaw UI to fully render, then inject a prompt
  // that will trigger a tool execution (and thus the Yellow Shield)
  setTimeout(() => {
    if (!win || win.isDestroyed()) return;
    win.webContents.executeJavaScript(`
      (function() {
        // Find the chat input field
        var input = document.querySelector('textarea, input[type="text"], [contenteditable="true"]');
        if (!input) {
          // Try shadow DOM (Lit components)
          var app = document.querySelector('openclaw-app');
          if (app && app.shadowRoot) {
            input = app.shadowRoot.querySelector('textarea, input[type="text"], [contenteditable="true"]');
          }
        }
        if (input) {
          // Set the value and dispatch input event
          var nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value') ||
                             Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
          if (nativeSetter && nativeSetter.set) {
            nativeSetter.set.call(input, 'Run the command: date');
            input.dispatchEvent(new Event('input', { bubbles: true }));
            console.log('[CROCbox] First prompt injected into chat input');
          } else {
            input.value = 'Run the command: date';
            input.dispatchEvent(new Event('input', { bubbles: true }));
            console.log('[CROCbox] First prompt injected (fallback)');
          }
        } else {
          console.log('[CROCbox] Could not find chat input for first prompt');
        }
      })();
    `).catch(() => {});
  }, 3000); // Wait 3s for UI to fully render
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

  // Shield Scoring Engine IPC — click handler
  ipcMain.handle('crocbox:shield-detail', function() {
    if (!currentShieldScore) return '<div style="padding:24px;color:#888">Shield score not yet computed.</div>';
    return getShieldDetailHTML(currentShieldScore, rentalSkiLevel);
  });
}
// ── Application lifecycle ──────────────────────────────────────
let mainWindow = null;
let gatewayConnection = null;
let gatewayToken = null;
let proxyServer = null;
let startupComplete = false; // Prevents premature quit during welcome screen
let currentShieldScore = null; // Shield Scoring Engine state
let rentalSkiLevel = 'beginner'; // Default Rental Ski level
let veStatus = 'unknown'; // Trust Network status: enrolled, local, error
let veAgentId = null; // VE agent ID (from enrollment)
app.whenReady().then(async () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   CROCbox v0.9.0 — Soft Launch       ║');
  console.log('  ║   The Agent Trust Layer for OpenClaw  ║');
  console.log('  ║   Shield Scoring Engine Edition       ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  // Step 0: Detect if OpenClaw is installed (G-3 fix)
  if (!detectOpenClaw()) {
    console.error('[CROCbox] OpenClaw not found on this system');
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'CROCbox — OpenClaw Required',
      message: 'CROCbox requires OpenClaw to be installed.',
      detail: 'OpenClaw is the AI agent engine that CROCbox wraps with its trust layer.\n\nTo install OpenClaw:\n1. Open Terminal\n2. Paste: curl -fsSL https://openclaw.ai/install.sh | bash\n3. Run: openclaw onboard --install-daemon\n4. Relaunch CROCbox',
      buttons: ['Quit']
    });
    app.quit();
    return;
  }
  console.log('[CROCbox] OpenClaw detected ✓');

  // Step 1: Read auth token
  gatewayToken = readGatewayToken();
  if (!gatewayToken) {
    console.error('[CROCbox] No Gateway auth token found');
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'CROCbox — Configuration Needed',
      message: 'CROCbox could not find your OpenClaw configuration.',
      detail: 'OpenClaw needs to be set up before CROCbox can connect.\n\nTo set up OpenClaw:\n1. Open Terminal\n2. Run: openclaw onboard\n3. Follow the setup wizard\n4. Relaunch CROCbox',
      buttons: ['Quit']
    });
    app.quit();
    return;
  }
  console.log('[CROCbox] Auth token loaded from openclaw.json ✓');

  // Step 2: Check Gateway — auto-start if not running (G-1, G-2 fix)
  console.log('[CROCbox] Checking Gateway at ' + GATEWAY_URL + '...');
  var running = await checkGatewayRunning();
  if (!running) {
    console.log('[CROCbox] Gateway not running — attempting auto-start...');
    running = await autoStartGateway();
    if (!running) {
      console.error('[CROCbox] Gateway could not be started');
      dialog.showMessageBoxSync({
        type: 'error',
        title: 'CROCbox — Gateway Not Available',
        message: 'CROCbox could not start the OpenClaw Gateway.',
        detail: 'The Gateway may need to be started manually.\n\nTo start the Gateway:\n1. Open Terminal\n2. Run: openclaw gateway\n3. Wait for "Gateway running" message\n4. Relaunch CROCbox\n\nIf this keeps happening, try: openclaw onboard --install-daemon',
        buttons: ['Quit']
      });
      app.quit();
      return;
    }
  }
  console.log('[CROCbox] Gateway is running ✓');

  // Step 3: Connect via WebSocket (CROCbox main process connection)
  try {
    gatewayConnection = await connectToGateway(gatewayToken);
    console.log('[CROCbox] Gateway connection established ✓');
  } catch (err) {
    console.error('[CROCbox] Gateway connection failed: ' + err.message);
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'CROCbox — Connection Failed',
      message: 'CROCbox connected to the Gateway but the handshake failed.',
      detail: 'Error: ' + err.message + '\n\nThis usually means the Gateway needs to be restarted.\n\n1. Open Terminal\n2. Run: openclaw gateway\n3. Relaunch CROCbox',
      buttons: ['Quit']
    });
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
    console.error('[CROCbox] Proxy start failed: ' + err.message);
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'CROCbox — Internal Error',
      message: 'CROCbox could not start its internal proxy.',
      detail: 'Error: ' + err.message + '\n\nThis may be caused by a port conflict. Try quitting all CROCbox instances and relaunching.',
      buttons: ['Quit']
    });
    app.quit();
    return;
  }

  // Step 5: First-launch welcome screen (OB-1)
  ensureStateDir();
  var firstLaunch = isFirstLaunch();
  if (firstLaunch) {
    console.log('[CROCbox] First launch detected — showing welcome screen');
    await showWelcomeScreen();
    markLaunched();
    console.log('[CROCbox] Welcome screen completed ✓');
  }

  // Step 6: Create the application window
  mainWindow = createWindow(gatewayConnection);
  console.log('[CROCbox] Application window created ✓');

  // Step 7: Wire Yellow Shield consent IPC (A.11)
  wireConsentIPC(mainWindow);

  // Step 8: Inject first prompt on first launch (OB-3)
  if (firstLaunch) {
    console.log('[CROCbox] Injecting first prompt for Magic Moment...');
    injectFirstPrompt(mainWindow);
  }

  // Step 9: Compute Shield Score from Gateway catalog (SSE-1 through SSE-4)
  try {
    console.log('[CROCbox] Requesting tools.catalog for Shield Score...');
    gatewayConnection.ws.send(JSON.stringify({
      type: 'req',
      id: 'crocbox-catalog-001',
      method: 'tools.catalog',
      params: {}
    }));
    // Listen for the catalog response
    var catalogHandler = function(data) {
      try {
        var msg = JSON.parse(data.toString());
        if (msg.type === 'res' && msg.id === 'crocbox-catalog-001' && msg.ok) {
          gatewayConnection.ws.removeListener('message', catalogHandler);
          console.log('[CROCbox] tools.catalog received — computing Shield Score');
          // Small delay to ensure window is fully loaded
          setTimeout(function() {
            computeAndInjectShield(mainWindow, msg.payload);
          }, 2000);
        }
      } catch (e) {}
    };
    gatewayConnection.ws.on('message', catalogHandler);
  } catch (err) {
    console.log('[CROCbox] Shield Score: could not request catalog — ' + err.message);
  }

  // Step 10: Check VE enrollment status (TN-4, TN-5, TN-6)
  console.log('[CROCbox] Checking Trust Network enrollment...');
  await checkVeEnrollment();
  // Inject Trust Network indicator after window loads
  setTimeout(function() {
    if (mainWindow && !mainWindow.isDestroyed()) {
      injectTrustNetworkIndicator(mainWindow, veStatus);
    }
  }, 3000);

  startupComplete = true;
  console.log('[CROCbox] ✓ CROCbox v0.9.0 ready');
  console.log('');
});
app.on('window-all-closed', async () => {
  // Don't quit if startup is still in progress (welcome screen closing)
  if (!startupComplete) {
    console.log('[CROCbox] Window closed during startup — not quitting yet');
    return;
  }
  console.log('[CROCbox] All windows closed — shutting down');
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
