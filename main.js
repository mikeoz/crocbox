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
// ── Bundled OpenClaw paths ─────────────────────────────────────
// In production (.app), resources are in Contents/Resources/
// In dev mode, we fall back to system OpenClaw
function getBundledPaths() {
  // Check 1: Already extracted to ~/.crocbox/openclaw/
  var extractedDir = path.join(CROCBOX_STATE_DIR, 'openclaw');
  var extractedNode = path.join(extractedDir, 'node', 'node');
  var extractedOC = path.join(extractedDir, 'openclaw', 'dist', 'index.js');
  if (fs.existsSync(extractedNode) && fs.existsSync(extractedOC)) {
    return { node: extractedNode, openclaw: extractedOC, bundled: true, extracted: true };
  }
  // Check 2: Archive in .app bundle (production) — needs extraction
  var archivePath = path.join(process.resourcesPath || '', 'bundled-openclaw.tar.gz');
  if (fs.existsSync(archivePath)) {
    return { node: null, openclaw: null, bundled: true, extracted: false, archivePath: archivePath };
  }
  // Check 3: Dev mode — uncompressed directory next to main.js
  var devNode = path.join(__dirname, 'bundled-openclaw', 'node', 'node');
  var devOC = path.join(__dirname, 'bundled-openclaw', 'openclaw', 'dist', 'index.js');
  if (fs.existsSync(devNode) && fs.existsSync(devOC)) {
    return { node: devNode, openclaw: devOC, bundled: true, extracted: true };
  }
  return { node: null, openclaw: null, bundled: false, extracted: false };
}

// ── Extract bundled archive on first launch ────────────────────
function extractBundledArchive(archivePath) {
  return new Promise(function(resolve) {
    var extractDir = path.join(CROCBOX_STATE_DIR, 'openclaw');
    console.log('[CROCbox] Extracting bundled OpenClaw to ' + extractDir + '...');
    fs.mkdirSync(extractDir, { recursive: true });
    var { exec } = require('child_process');
    exec('tar xzf "' + archivePath + '" -C "' + extractDir + '"', { timeout: 120000 }, function(err) {
      if (err) {
        console.log('[CROCbox] Extraction failed: ' + err.message);
        resolve(false);
      } else {
        // Verify extraction
        var nodeCheck = path.join(extractDir, 'node', 'node');
        var ocCheck = path.join(extractDir, 'openclaw', 'dist', 'index.js');
        if (fs.existsSync(nodeCheck) && fs.existsSync(ocCheck)) {
          // Make node executable
          fs.chmodSync(nodeCheck, 0o755);
          console.log('[CROCbox] Extraction complete');
          resolve(true);
        } else {
          console.log('[CROCbox] Extraction incomplete — missing files');
          resolve(false);
        }
      }
    });
  });
}
// ── Create OpenClaw config for bundled mode ────────────────────
function ensureOpenClawConfig() {
  var ocDir = path.join(process.env.HOME || '/tmp', '.openclaw');
  var configPath = path.join(ocDir, 'openclaw.json');
  var authDir = path.join(ocDir, 'agents', 'main', 'agent');
  var authPath = path.join(authDir, 'auth-profiles.json');

  // Create directory structure
  if (!fs.existsSync(ocDir)) fs.mkdirSync(ocDir, { recursive: true });
  if (!fs.existsSync(authDir)) fs.mkdirSync(authDir, { recursive: true });

  // Ensure config has gateway auth token (merge if file exists)
  var config = {};
  if (fs.existsSync(configPath)) {
    try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (e) { config = {}; }
  }
  if (!config.gateway) config.gateway = {};
  if (!config.gateway.port) config.gateway.port = GATEWAY_PORT;
  if (!config.gateway.auth) config.gateway.auth = {};
  if (!config.gateway.auth.token) {
    config.gateway.auth.token = require('crypto').randomBytes(32).toString('hex');
    console.log('[CROCbox] Generated new Gateway auth token');
  }
  if (!config.gateway.mode) config.gateway.mode = 'local';
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
  console.log('[CROCbox] OpenClaw config ensured: ' + configPath);

  // Write embedded API key if auth-profiles not present
  if (!fs.existsSync(authPath)) {
    var authProfiles = {
      version: 1,
      profiles: {
        'anthropic:default': {
          type: 'api_key',
          provider: 'anthropic',
          key: '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'
        }
      },
      usageStats: {}
    };
    fs.writeFileSync(authPath, JSON.stringify(authProfiles, null, 2), 'utf8');
    console.log('[CROCbox] Embedded API key written to auth-profiles');
  }
}
let bundledGatewayProcess = null; // Track the spawned Gateway for cleanup
// ── Start Gateway from bundle ──────────────────────────────────
function startBundledGateway(bundledPaths) {
  return new Promise((resolve) => {
    console.log('[CROCbox] Starting bundled Gateway...');
    console.log('[CROCbox]   Node: ' + bundledPaths.node);
    console.log('[CROCbox]   OpenClaw: ' + bundledPaths.openclaw);
    var { spawn } = require('child_process');
    var gw = spawn(bundledPaths.node, [bundledPaths.openclaw, 'gateway', '--port', String(GATEWAY_PORT), '--allow-unconfigured'], {
      cwd: process.env.HOME || '/tmp',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: Object.assign({}, process.env, {
        HOME: process.env.HOME,
        PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || '')
      })
    });
    bundledGatewayProcess = gw;
    gw.stdout.on('data', function(d) {
      var line = d.toString().trim();
      if (line) console.log('[BundledGW] ' + line);
    });
    gw.stderr.on('data', function(d) {
      var line = d.toString().trim();
      if (line) console.log('[BundledGW:err] ' + line);
    });
    gw.on('error', function(err) {
      console.log('[CROCbox] Bundled Gateway spawn error: ' + err.message);
      resolve(false);
    });
    // Poll for Gateway to become available
    var attempts = 0;
    var maxAttempts = 30;
    var poll = setInterval(async function() {
      attempts++;
      var running = await checkGatewayRunning();
      if (running) {
        clearInterval(poll);
        console.log('[CROCbox] Bundled Gateway running (' + (attempts * 0.5) + 's)');
        resolve(true);
      } else if (attempts >= maxAttempts) {
        clearInterval(poll);
        console.log('[CROCbox] Bundled Gateway did not start within 15s');
        resolve(false);
      }
    }, 500);
  });
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
        cwd: process.env.HOME || '/tmp',
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
// ── BigCROC Workspace Seeding ────────────────────────────────
function seedBigCROCWorkspace() {
  const wsPath = require("path").join(require("os").homedir(), ".openclaw", "workspace");
  try {
    var cur = fs.readFileSync(require("path").join(wsPath, "SOUL.md"), "utf8");
    if (cur.includes("BigCROC")) { console.log("[CROCbox] BigCROC workspace already seeded"); return; }
  } catch(e) {}
  try { fs.mkdirSync(wsPath, { recursive: true }); } catch(e) {}
  ["SOUL.md","IDENTITY.md","USER.md","AGENTS.md"].forEach(function(f) {
    try { var p = require("path").join(wsPath, f); if (fs.existsSync(p)) fs.copyFileSync(p, p+".bak-pre-bigcroc"); } catch(e) {}
  });
  fs.writeFileSync(require("path").join(wsPath, "SOUL.md"), BIGCROC_WS.soul, "utf8");
  fs.writeFileSync(require("path").join(wsPath, "IDENTITY.md"), BIGCROC_WS.identity, "utf8");
  fs.writeFileSync(require("path").join(wsPath, "USER.md"), BIGCROC_WS.user, "utf8");
  fs.writeFileSync(require("path").join(wsPath, "AGENTS.md"), BIGCROC_WS.agents, "utf8");
  console.log("[CROCbox] BigCROC workspace seeded");
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
      if ('${status}' === 'local') { el.style.cursor = 'pointer'; el.title = 'Click to activate your CROCbox'; el.addEventListener('click', function() { if (window.crocbox && window.crocbox.activate) window.crocbox.activate(); }); }
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

// ── Account Activation (localhost callback server) ──────────
let activationServer = null;
function startActivationFlow(win) {
  const http = require('http');
  const { shell } = require('electron');
  // Find a free port
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const accountId = url.searchParams.get('account_id');
    const email = url.searchParams.get('email');
    if (accountId) {
      console.log('[CROCbox] Activation callback received: account_id=' + accountId);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body style="background:#1a1a1a;color:#ccc;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2 style="color:#d4a017">CROCbox Activated</h2><p>You can close this tab and return to CROCbox.</p></div></body></html>');
      // Complete enrollment
      completeActivation(win, accountId, email);
      // Shut down callback server after a short delay
      setTimeout(() => {
        if (activationServer) { activationServer.close(); activationServer = null; }
      }, 2000);
    } else {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Missing account_id parameter');
    }
  });
  srv.listen(0, '127.0.0.1', () => {
    const port = srv.address().port;
    activationServer = srv;
    const connectUrl = 'https://opn.li/connect?callback=' + encodeURIComponent('http://127.0.0.1:' + port);
    console.log('[CROCbox] Opening activation: ' + connectUrl);
    shell.openExternal(connectUrl);
  });
  srv.on('error', (err) => {
    console.log('[CROCbox] Activation server error: ' + err.message);
  });
}

async function completeActivation(win, accountId, email) {
  try {
    console.log('[CROCbox] Enrolling with VE...');
    var result = await veEnroll(accountId, rentalSkiLevel);
    if (result && result.agent_id) {
      veStatus = 'enrolled';
      veAgentId = result.agent_id;
      console.log('[CROCbox] VE enrollment complete: agent_id=' + result.agent_id);
      // Save account info locally
      var statePath = require('path').join(require('os').homedir(), '.crocbox');
      try { fs.mkdirSync(statePath, { recursive: true }); } catch(e) {}
      fs.writeFileSync(require('path').join(statePath, 'account.json'),
        JSON.stringify({ account_id: accountId, email: email || '', agent_id: result.agent_id, activated: new Date().toISOString(), firstRun: true }), 'utf8');
      // Update the indicator
      if (win && !win.isDestroyed()) {
        injectTrustNetworkIndicator(win, 'enrolled');
      }
    } else {
      console.log('[CROCbox] VE enrollment returned no agent_id — staying in local mode');
    }
  } catch (err) {
    console.log('[CROCbox] VE enrollment failed: ' + err.message + ' — staying in local mode');
  }
}

// ── Trust Activity Viewer ────────────────────────────────────
function openTrustActivity() {
  const { BrowserWindow } = require('electron');
  const path = require('path');
  const os = require('os');
  const logPath = path.join(os.homedir(), 'opnli', 'crocbox', 'logs', 'crocbox-audit.jsonl');
  let entries = [];
  try {
    const raw = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    entries = raw.map(function(line) {
      try { return JSON.parse(line); } catch(e) { return null; }
    }).filter(Boolean).reverse(); // newest first
  } catch(e) {
    entries = [];
  }
  // Build rows
  var rows = entries.slice(0, 200).map(function(e) {
    var icon = e.result === 'allowed' ? '<span style="color:#22C55E">&#x2714;</span>'
             : e.result === 'blocked' ? '<span style="color:#EF4444">&#x2718;</span>'
             : e.result === 'intercepted' ? '<span style="color:#EAB308">&#x25CF;</span>'
             : '<span style="color:#888">&#x25CB;</span>';
    var action = e.action === 'yellow-shield' ? 'Yellow Shield' : e.action || 'unknown';
    var target = (e.target || '').length > 50 ? (e.target || '').substring(0, 47) + '...' : (e.target || '');
    var reason = (e.reason || '').replace(/-/g, ' ');
    var time = '';
    try {
      var d = new Date(e.timestamp);
      time = d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    } catch(x) { time = e.timestamp || ''; }
    var shield = e.shield ? '<span style="color:#EAB308;font-size:10px">&#x25C6; ' + e.shield + '</span>' : '';
    return '<tr><td style="padding:6px 10px;border-bottom:1px solid #333;color:#888;font-size:11px;white-space:nowrap">' + time + '</td>'
         + '<td style="padding:6px 10px;border-bottom:1px solid #333;text-align:center">' + icon + '</td>'
         + '<td style="padding:6px 10px;border-bottom:1px solid #333;color:#ccc;font-size:12px">' + action + ' ' + shield + '</td>'
         + '<td style="padding:6px 10px;border-bottom:1px solid #333;color:#999;font-size:11px;font-family:monospace">' + target + '</td>'
         + '<td style="padding:6px 10px;border-bottom:1px solid #333;color:#777;font-size:11px">' + reason + '</td></tr>';
  }).join('');
  var totalAllowed = entries.filter(function(e){ return e.result === 'allowed'; }).length;
  var totalBlocked = entries.filter(function(e){ return e.result === 'blocked'; }).length;
  var totalIntercepted = entries.filter(function(e){ return e.result === 'intercepted'; }).length;
  var html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Trust Activity</title>'
    + '<style>body{margin:0;padding:0;background:#1a1a1a;color:#ccc;font-family:-apple-system,sans-serif;}'
    + '.header{padding:16px 20px;border-bottom:1px solid #333;display:flex;align-items:center;justify-content:space-between}'
    + '.title{font-size:16px;font-weight:600;color:#f0f0f0}'
    + '.stats{display:flex;gap:16px;font-size:11px}'
    + '.stat{display:flex;align-items:center;gap:4px}'
    + 'table{width:100%;border-collapse:collapse}'
    + 'th{text-align:left;padding:8px 10px;border-bottom:1px solid #444;color:#888;font-size:10px;text-transform:uppercase;font-weight:500}'
    + '.empty{text-align:center;padding:40px;color:#666;font-size:14px}'
    + '</style></head><body>'
    + '<div class="header"><span class="title">Trust Activity</span>'
    + '<div class="stats">'
    + '<div class="stat"><span style="color:#22C55E">&#x2714;</span> ' + totalAllowed + ' allowed</div>'
    + '<div class="stat"><span style="color:#EF4444">&#x2718;</span> ' + totalBlocked + ' blocked</div>'
    + '<div class="stat"><span style="color:#EAB308">&#x25CF;</span> ' + totalIntercepted + ' intercepted</div>'
    + '<div class="stat" style="color:#555">' + entries.length + ' total</div>'
    + '</div></div>'
    + (entries.length === 0
      ? '<div class="empty">No activity yet. Use your AI and the audit trail will appear here.</div>'
      : '<table><thead><tr><th>Time</th><th></th><th>Action</th><th>Target</th><th>Decision</th></tr></thead><tbody>' + rows + '</tbody></table>')
    + '</body></html>';
  var actWin = new BrowserWindow({
    width: 720, height: 520, title: 'Trust Activity — CROCbox',
    backgroundColor: '#1a1a1a',
    webPreferences: { nodeIntegration: false, contextIsolation: true }
  });
  actWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  actWin.setMenuBarVisibility(false);
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
              detail.innerHTML = html + '<div style="padding:8px 20px 16px;text-align:center;border-top:1px solid #333"><a id="crocbox-activity-link" href="#" style="color:#d4a017;font-size:11px;text-decoration:none;cursor:pointer">View Trust Activity</a></div>';
              setTimeout(function(){ var al = document.getElementById('crocbox-activity-link'); if(al) al.addEventListener('click', function(ev){ ev.preventDefault(); if(window.crocbox&&window.crocbox.openTrustActivity) window.crocbox.openTrustActivity(); }); }, 100);
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
  <div class="shield"><svg width="72" height="86" viewBox="0 0 100 120" style="display:inline-block"><path d="M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z" fill="#58585C" stroke="#707074" stroke-width="1.5"/><path d="M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z" fill="#CA8A04"/><path d="M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z" fill="#EAB308"/></svg></div>
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
  // Wait for the OpenClaw UI to fully render, then auto-send a prompt
  // that triggers BigCROC's First Contact Protocol
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
            nativeSetter.set.call(input, 'I just activated my CROCbox. Who are you and what can you do?');
            input.dispatchEvent(new Event('input', { bubbles: true }));
            console.log('[CROCbox] First prompt set — auto-sending...');
            // Auto-click Send button after a brief pause
            setTimeout(function() {
              var sendBtn = document.querySelector('button[class*="send"], button[aria-label*="Send"], button[title*="Send"]');
              if (!sendBtn) {
                // Try finding by text content
                var btns = document.querySelectorAll('button');
                for (var b = 0; b < btns.length; b++) {
                  if (btns[b].textContent.trim() === 'Send' || btns[b].querySelector('svg')) {
                    var rect = btns[b].getBoundingClientRect();
                    if (rect.bottom > window.innerHeight - 100) { sendBtn = btns[b]; break; }
                  }
                }
              }
              if (sendBtn) {
                sendBtn.click();
                console.log('[CROCbox] First prompt auto-sent');
              } else {
                console.log('[CROCbox] Could not find Send button — prompt is pre-filled, user must click Send');
              }
            }, 500);
          } else {
            input.value = 'I just activated my CROCbox. Who are you and what can you do?';
            input.dispatchEvent(new Event('input', { bubbles: true }));
            console.log('[CROCbox] First prompt set (fallback) — auto-sending...');
            setTimeout(function() {
              var sendBtn = document.querySelector('button[class*="send"], button[aria-label*="Send"]');
              if (!sendBtn) {
                var btns = document.querySelectorAll('button');
                for (var b = 0; b < btns.length; b++) {
                  if (btns[b].textContent.trim() === 'Send') { sendBtn = btns[b]; break; }
                }
              }
              if (sendBtn) { sendBtn.click(); console.log('[CROCbox] First prompt auto-sent (fallback)'); }
            }, 500);
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
        overlay.innerHTML = '<div style="padding:24px 24px 16px; border-bottom:1px solid rgba(212,160,23,0.3)"><div style="text-align:center; margin-bottom:8px"><svg width=\"48\" height=\"58\" viewBox=\"0 0 100 120\" style=\"display:inline-block\"><path d=\"M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z\" fill=\"#58585C\" stroke=\"#707074\" stroke-width=\"3\"/><path d=\"M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z\" fill=\"#CA8A04\"/><path d=\"M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z\" fill=\"#EAB308\"/></svg></div><div style="font-size:17px; font-weight:600; color:#d4a017; margin-bottom:6px">Yellow Shield</div><div style="font-size:13px; color:#999">Action Detected</div></div><div style="flex:1; padding:20px 24px"><div style="font-size:14px; color:#ccc; line-height:1.6; margin-bottom:16px">Your AI executed an action. The result is ready but has <strong>not been delivered</strong> yet.<br><br><strong>You decide what happens next.</strong></div><div style="background:rgba(212,160,23,0.1); border:1px solid rgba(212,160,23,0.25); border-radius:8px; padding:12px; font-size:12px; color:#b0b0b0; line-height:1.5">Yellow Shield means the action already ran. CROCbox controls whether the result reaches you.</div></div><div style="padding:16px 24px 24px; display:flex; gap:12px"><button id="crocbox-btn-allow">Allow Result</button><button id="crocbox-btn-deny">Block Result</button></div>';
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
  
  // Trust Activity IPC: renderer can open activity viewer
  ipcMain.handle('crocbox:trust-activity', () => {
    openTrustActivity();
    return true;
  });
  // Activation IPC: renderer can trigger account activation
  ipcMain.handle('crocbox:activate', () => {
    startActivationFlow(mainWindow);
    return true;
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
const BIGCROC_WS = require('./bigcroc-workspace');
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
  console.log('  ║   CROCbox v1.0.0 — Day One       ║');
  console.log('  ║   The Agent Trust Layer for OpenClaw  ║');
  console.log('  ║   Shield Scoring Engine Edition       ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  // Step 0: Detect OpenClaw — system or bundled
  var useSystemOC = detectOpenClaw();
  var bundled = getBundledPaths();

  if (!useSystemOC && !bundled.bundled) {
    console.error('[CROCbox] No OpenClaw available (system or bundled)');
    dialog.showMessageBoxSync({
      type: 'error',
      title: 'CROCbox — Setup Error',
      message: 'CROCbox could not find its AI engine.',
      detail: 'The application bundle may be damaged. Please re-download CROCbox from GitHub.',
      buttons: ['Quit']
    });
    app.quit();
    return;
  }

  if (!useSystemOC && bundled.bundled) {
    console.log('[CROCbox] System OpenClaw not found — using bundled copy');
    // Extract archive if needed (first launch from .app)
    if (!bundled.extracted && bundled.archivePath) {
      console.log('[CROCbox] First launch — extracting bundled OpenClaw...');
      var extracted = await extractBundledArchive(bundled.archivePath);
      if (!extracted) {
        dialog.showMessageBoxSync({
          type: 'error',
          title: 'CROCbox — Setup Error',
          message: 'CROCbox could not extract its AI engine.',
          detail: 'Please re-download CROCbox from GitHub.',
          buttons: ['Quit']
        });
        app.quit();
        return;
      }
      // Re-check paths after extraction
      bundled = getBundledPaths();
    }
    ensureOpenClawConfig();
  }
  console.log('[CROCbox] OpenClaw: ' + (useSystemOC ? 'system' : 'bundled') + ' ✓');

  // Step 1: Read auth token
  gatewayToken = readGatewayToken();
  if (!gatewayToken) {
    if (!useSystemOC && bundled.bundled) {
      ensureOpenClawConfig();
      gatewayToken = readGatewayToken();
    }
    if (!gatewayToken) {
      dialog.showMessageBoxSync({
        type: 'error',
        title: 'CROCbox — Configuration Error',
        message: 'CROCbox could not find the AI configuration.',
        detail: 'Please re-download CROCbox from GitHub.',
        buttons: ['Quit']
      });
      app.quit();
      return;
    }
  }
  console.log('[CROCbox] Auth token loaded ✓');

  // Step 2: Start Gateway — system auto-start or bundled
  console.log('[CROCbox] Checking Gateway at ' + GATEWAY_URL + '...');
  var running = await checkGatewayRunning();
  if (!running) {
    if (useSystemOC) {
      console.log('[CROCbox] Auto-starting system Gateway...');
      running = await autoStartGateway();
    }
    if (!running && bundled.bundled) {
      console.log('[CROCbox] Starting bundled Gateway...');
      running = await startBundledGateway(bundled);
    }
    if (!running) {
      dialog.showMessageBoxSync({
        type: 'error',
        title: 'CROCbox — Gateway Error',
        message: 'CROCbox could not start the AI engine.',
        detail: 'Please try relaunching. If this persists, re-download from GitHub.',
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

  // Step 4.5: Seed BigCROC workspace files
  seedBigCROCWorkspace();
  // Step 5: First-launch welcome screen (OB-1)
  ensureStateDir();
  var firstLaunch = isFirstLaunch();
  if (firstLaunch) {
    console.log('[CROCbox] First launch detected — showing welcome screen');
    await showWelcomeScreen();
    markLaunched();
    console.log('[CROCbox] Welcome screen completed ✓');
    // Step 5.5: Automatic account activation
    console.log('[CROCbox] Starting account activation...');
    try {
      await new Promise((resolve, reject) => {
        const http = require('http');
        const { shell } = require('electron');
        const srv = http.createServer((req, res) => {
          const url = new URL(req.url, 'http://127.0.0.1');
          const accountId = url.searchParams.get('account_id');
          const email = url.searchParams.get('email');
          if (accountId) {
            console.log('[CROCbox] Activation callback received: account_id=' + accountId);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body style="background:#1a1a1a;color:#ccc;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2 style="color:#d4a017">CROCbox Activated</h2><p>You can close this tab and return to CROCbox.</p></div></body></html>');
            // Save account and enroll
            completeActivation(null, accountId, email).then(() => {
              setTimeout(() => { srv.close(); resolve(); }, 1000);
            }).catch(() => {
              setTimeout(() => { srv.close(); resolve(); }, 1000);
            });
          } else {
            res.writeHead(400);
            res.end('Missing account_id');
          }
        });
        srv.listen(0, '127.0.0.1', () => {
          const port = srv.address().port;
          const connectUrl = 'https://opn.li/connect?callback=' + encodeURIComponent('http://127.0.0.1:' + port);
          console.log('[CROCbox] Opening activation: ' + connectUrl);
          shell.openExternal(connectUrl);
        });
        srv.on('error', (err) => {
          console.log('[CROCbox] Activation server error: ' + err.message);
          resolve(); // Don't block startup on error
        });
        // Timeout after 5 minutes — don't block forever
        setTimeout(() => {
          console.log('[CROCbox] Activation timeout — continuing in local mode');
          try { srv.close(); } catch(e) {}
          resolve();
        }, 300000);
      });
      console.log('[CROCbox] Account activation completed ✓');
    } catch (err) {
      console.log('[CROCbox] Account activation skipped: ' + err.message);
    }
  }

  // Step 6: Create the application window
  mainWindow = createWindow(gatewayConnection);
  console.log('[CROCbox] Application window created ✓');

  // Step 7: Wire Yellow Shield consent IPC (A.11)
  wireConsentIPC(mainWindow);

  // Step 8: Inject first prompt on first launch (OB-3)
  if (firstLaunch) {
    console.log('[CROCbox] Injecting BigCROC First Contact trigger...');
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

  // Step 9.5: Check for saved Opn.li account
  try {
    var savedAccount = JSON.parse(fs.readFileSync(require('path').join(require('os').homedir(), '.crocbox', 'account.json'), 'utf8'));
    if (savedAccount.agent_id) {
      veAgentId = savedAccount.agent_id;
      console.log('[CROCbox] Saved account found: ' + savedAccount.email + ' (agent_id=' + savedAccount.agent_id + ')');
    }
  } catch (e) { /* no saved account — first launch */ }
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
  console.log('[CROCbox] ✓ CROCbox v1.0.0 ready');
  console.log('');
});
app.on('window-all-closed', async () => {
  // Don't quit if startup is still in progress (welcome screen closing)
  if (!startupComplete) {
    console.log('[CROCbox] Window closed during startup — not quitting yet');
    return;
  }
  console.log('[CROCbox] All windows closed — shutting down');
  // Kill bundled Gateway if we started it
  if (bundledGatewayProcess) {
    console.log('[CROCbox] Stopping bundled Gateway...');
    try { bundledGatewayProcess.kill(); } catch (e) {}
    bundledGatewayProcess = null;
  }
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
