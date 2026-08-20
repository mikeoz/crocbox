/**
 * CROCbox v1.0.0-beta.14 — Electron Main Process
 * 
 * Phase 1: Gateway Connection (with auto-start + native error dialogs)
 * Phase 2: BrowserWindow + Control UI
 * A.7: Auth token auto-injected via proxy HTML injection
 * A.8: WebSocket MITM proxy with HTTP proxying and WS redirect
 * A.12: Green Shield consent + Controls Panel IPC
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
 * @see OPN_ENG_v08-Architecture_15MAR26_v1, Section 3.2
 * @see OPN_PM_FullCROC-Mode_16MAR26_v2, Section 5
 */
// Guard against EPIPE crashes when stdout pipe is closed (e.g., | head)
process.stdout.on('error', (err) => { if (err.code === 'EPIPE') process.exit(0); });
process.stderr.on('error', (err) => { if (err.code === 'EPIPE') process.exit(0); });

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { execSync } = require('child_process');
const WebSocket = require('ws');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
// ── MITM Proxy Module ──────────────────────────────────────────

// ── File-based logger (captures console output to disk) ────────
const LOG_DIR = require('path').join(process.env.HOME || '/tmp', 'opnli', 'crocbox', 'logs');
try { if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true }); } catch(e) {}
const LOG_PATH = require('path').join(LOG_DIR, 'electron.log');
const logStream = fs.createWriteStream(LOG_PATH, { flags: 'a' });
const origLog = console.log;
const origWarn = console.warn;
const origError = console.error;
function stampedWrite(prefix, args) {
  const line = new Date().toISOString() + ' ' + prefix + ' ' + Array.from(args).map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
  try { logStream.write(line + '\n'); } catch(e) {}
}
console.log = function() { origLog.apply(console, arguments); stampedWrite('LOG', arguments); };
console.warn = function() { origWarn.apply(console, arguments); stampedWrite('WARN', arguments); };
console.error = function() { origError.apply(console, arguments); stampedWrite('ERR', arguments); };
const { startProxy, stopProxy, setGreenShieldActive, PROXY_PORT } = require('./ws-proxy');
const { computeShieldScore, getShieldDetailHTML, parseCatalog } = require('./shield-score');

// S3: Parse .env BEFORE requiring green-shield-gate, which reads
// CONSENT_SERVER_URL, CONSENT_SUBMIT_SECRET, and CROCBOX_MEMBER_ID
// at module load time. Without this, the DMG launch has no OTN credentials.
// Only sets vars not already in process.env, so explicit overrides win.
(function parseEnvFile() {
  var p = require('path');
  var fs = require('fs');
  var appSupport = p.join(process.env.HOME || '/tmp', 'Library', 'Application Support', 'CROCbox', '.env');
  var dev = p.join(process.env.HOME || '/tmp', 'opnli', 'crocbox', '.env');
  var envPath = fs.existsSync(appSupport) ? appSupport : dev;
  process.env.CROCBOX_ENV_PATH = envPath;
  if (!fs.existsSync(envPath)) {
    console.error('[CROCbox] .env not found at ' + envPath + ' — OTN credentials will be missing');
    return;
  }
  try {
    var lines = fs.readFileSync(envPath, 'utf8').split('\n');
    var count = 0;
    lines.forEach(function(line) {
      line = line.trim();
      if (!line || line.charAt(0) === '#') return;
      var eq = line.indexOf('=');
      if (eq < 1) return;
      var key = line.substring(0, eq).trim();
      var val = line.substring(eq + 1).trim();
      // Strip surrounding quotes if present
      if ((val.charAt(0) === '"' && val.charAt(val.length - 1) === '"') ||
          (val.charAt(0) === "'" && val.charAt(val.length - 1) === "'")) {
        val = val.substring(1, val.length - 1);
      }
      if (!process.env[key]) {
        process.env[key] = val;
        count++;
      }
    });
    console.log('[CROCbox] .env parsed: ' + count + ' vars set from ' + envPath);
  } catch (e) {
    console.error('[CROCbox] .env parse failed: ' + e.message);
  }
})();

const { startGreenShieldServer, stopGreenShieldServer, resolveGreenConsent, setConsentCallback, setTimeoutCallback, setReceiptCallback, setRuleAppliedCallback, GREEN_SHIELD_PORT } = require('./green-shield-gate');
const agentSync = require('./agent-sync');
if (!process.env.VE_ENDPOINT) { process.env.VE_ENDPOINT = 'https://ve-staging.opn.li'; } // Beta fallback — see GT-17 in SessionCloseout
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
// ── Trust.md management ─────────────────────────────────────────
function ensureTrustMd() {
  var trustDir = path.join(process.env.HOME || '/tmp', 'opnli', 'crocbox');
  var trustDest = path.join(trustDir, 'Trust.md');
  if (!fs.existsSync(trustDir)) fs.mkdirSync(trustDir, { recursive: true });
  // Copy Trust.md from app bundle if not present (or update on version change)
  var bundledTrust = path.join(__dirname, 'Trust.md');
  if (fs.existsSync(bundledTrust)) {
    var shouldWrite = !fs.existsSync(trustDest);
    if (!shouldWrite) {
      // Update if bundled version is different (CROCbox update)
      var bundled = fs.readFileSync(bundledTrust, 'utf8');
      var existing = fs.readFileSync(trustDest, 'utf8');
      shouldWrite = (bundled !== existing);
    }
    if (shouldWrite) {
      fs.copyFileSync(bundledTrust, trustDest);
      console.log('[CROCbox] Trust.md installed: ' + trustDest);
    }
  }
  return trustDest;
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
  // Set default model to Sonnet (higher rate limits, lower cost, quality conversation)
  if (!config.agents) config.agents = {};
  if (!config.agents.defaults) config.agents.defaults = {};
  if (!config.agents.defaults.model) config.agents.defaults.model = {};
  if (!config.agents.defaults.model.primary) {
    config.agents.defaults.model.primary = 'anthropic/claude-sonnet-4-6';
    console.log('[CROCbox] Default model set to Claude Sonnet 4');
  }
  // Remove unrecognized keys that crash newer Gateway versions
  if (config.web) {
    delete config.web;
    console.log('[CROCbox] Removed legacy web.brave config (Gateway rejects unrecognized keys)');
  }
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
  console.log('[CROCbox] OpenClaw config ensured: ' + configPath);

  // API key is delivered during activation (keyCARD delivery)
  // No embedded .api-key file needed — activation callback writes auth-profiles.json
  if (!fs.existsSync(authPath)) {
    console.log('[CROCbox] No auth-profiles.json yet — will be created during activation');
  } else {
    console.log('[CROCbox] auth-profiles.json exists: ' + authPath);
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
        PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || ''),
        BRAVE_API_KEY: 'BSADrBk5rw1zp2STg_hZhjc2WuPMTTp'
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
  // Check CLI install first (openclaw-cli via Homebrew)
  try {
    const result = require('child_process').execSync('which openclaw 2>/dev/null', { encoding: 'utf8' }).trim();
    if (result) {
      console.log('[CROCbox] OpenClaw found at: ' + result + ' (CLI)');
      return true;
    }
  } catch (e) {}
  // Check Cask install (/Applications/OpenClaw.app)
  if (fs.existsSync('/Applications/OpenClaw.app')) {
    console.log('[CROCbox] OpenClaw found at: /Applications/OpenClaw.app (Cask)');
    return true;
  }
  return false;
}

// ── Classify Installation Scenario ─────────────────────────────
// Returns: 'NHB' | 'EXISTING_OC' | 'UPGRADE'
// NHB: Clean machine, no OpenClaw. Full first-launch flow.
// EXISTING_OC: User has OpenClaw installed and configured. Non-invasive wrap.
// UPGRADE: User has a prior CROCbox installation. Update CROCbox files only.
function classifyInstallation() {
  var home = process.env.HOME || '/tmp';
  var ocConfigPath = require('path').join(home, '.openclaw', 'openclaw.json');
  var authProfilesPath = require('path').join(home, '.openclaw', 'agents', 'main', 'agent', 'auth-profiles.json');
  var crocboxLaunched = require('path').join(home, '.crocbox', 'launched');

  // Check 1: Has CROCbox been launched before?
  if (fs.existsSync(crocboxLaunched)) {
    console.log('[CROCbox] Classification: UPGRADE (prior CROCbox installation detected)');
    return 'UPGRADE';
  }

  // Check 2: Is OpenClaw installed and fully configured?
  // D-1: Check both CLI install (which openclaw) and Cask install (/Applications/OpenClaw.app)
  var hasSystemOC = false;
  var ocInstallType = 'none';
  try {
    var result = require('child_process').execSync('which openclaw 2>/dev/null', { encoding: 'utf8' }).trim();
    if (result) { hasSystemOC = true; ocInstallType = 'cli'; }
  } catch (e) {}
  if (!hasSystemOC && fs.existsSync('/Applications/OpenClaw.app')) {
    hasSystemOC = true;
    ocInstallType = 'cask';
  }

  var hasConfig = false;
  try {
    var config = JSON.parse(fs.readFileSync(ocConfigPath, 'utf8'));
    hasConfig = !!(config.gateway && config.gateway.auth && config.gateway.auth.token);
  } catch (e) {}

  var hasApiKey = false;
  try {
    var profiles = JSON.parse(fs.readFileSync(authProfilesPath, 'utf8'));
    if (profiles.profiles) {
      hasApiKey = Object.keys(profiles.profiles).some(function(k) {
        return profiles.profiles[k] && (profiles.profiles[k].apiKey || profiles.profiles[k].key);
      });
    }
  } catch (e) {}

  if (hasSystemOC && hasConfig && hasApiKey) {
    console.log('[CROCbox] Classification: EXISTING_OC');
    console.log('[CROCbox]   System OpenClaw: ' + (hasSystemOC ? 'YES (' + ocInstallType + ')' : 'NO'));
    console.log('[CROCbox]   Config with token: ' + (hasConfig ? 'YES' : 'NO'));
    console.log('[CROCbox]   API key configured: ' + (hasApiKey ? 'YES' : 'NO'));
    return 'EXISTING_OC';
  }

  console.log('[CROCbox] Classification: NHB (clean machine)');
  console.log('[CROCbox]   System OpenClaw: ' + (hasSystemOC ? 'YES' : 'NO'));
  console.log('[CROCbox]   Config with token: ' + (hasConfig ? 'YES' : 'NO'));
  console.log('[CROCbox]   API key configured: ' + (hasApiKey ? 'YES' : 'NO'));
  return 'NHB';
}
// ── Auto-start Gateway if not running ──────────────────────────
function autoStartGateway() {
  return new Promise((resolve) => {
    console.log('[CROCbox] Attempting to auto-start Gateway...');
    // Check if openclaw CLI is available before trying to spawn
    var hasCliBinary = false;
    try {
      var which = require('child_process').execSync('which openclaw 2>/dev/null', { encoding: 'utf8' }).trim();
      hasCliBinary = !!which;
    } catch (e) {}
    if (!hasCliBinary) {
      // Cask user — cannot spawn CLI binary. Show friendly message.
      console.log('[CROCbox] No openclaw CLI found — Cask-only installation');
      var { dialog } = require('electron');
      dialog.showMessageBoxSync({
        type: 'info',
        title: 'CROCbox — Please Launch OpenClaw',
        message: 'CROCbox detected your OpenClaw installation, but the Gateway is not running.',
        detail: 'Please open OpenClaw from your Applications folder first, then relaunch CROCbox. CROCbox will wrap your running OpenClaw in the trust layer without changing anything.',
        buttons: ['OK']
      });
      resolve(false);
      return;
    }
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
    if (cur.includes("BigCROC")) {
      // Upgrade check: seed Trust.md if missing (added in alpha.12)
      if (BIGCROC_WS.trust) {
        var trustPath = require("path").join(wsPath, "Trust.md");
        if (!fs.existsSync(trustPath)) {
          fs.writeFileSync(trustPath, BIGCROC_WS.trust, "utf8");
          console.log("[CROCbox] Trust.md seeded on upgrade");
        }
      }
      console.log("[CROCbox] BigCROC workspace already seeded"); return;
    }
  } catch(e) {}
  try { fs.mkdirSync(wsPath, { recursive: true }); } catch(e) {}
  ["SOUL.md","IDENTITY.md","USER.md","AGENTS.md"].forEach(function(f) {
    try { var p = require("path").join(wsPath, f); if (fs.existsSync(p)) fs.copyFileSync(p, p+".bak-pre-bigcroc"); } catch(e) {}
  });
  fs.writeFileSync(require("path").join(wsPath, "SOUL.md"), BIGCROC_WS.soul, "utf8");
  fs.writeFileSync(require("path").join(wsPath, "IDENTITY.md"), BIGCROC_WS.identity, "utf8");
  fs.writeFileSync(require("path").join(wsPath, "USER.md"), BIGCROC_WS.user, "utf8");
  fs.writeFileSync(require("path").join(wsPath, "AGENTS.md"), BIGCROC_WS.agents, "utf8");
  if (BIGCROC_WS.trust) fs.writeFileSync(require("path").join(wsPath, "Trust.md"), BIGCROC_WS.trust, "utf8");
  console.log("[CROCbox] BigCROC workspace seeded");
}
// ── BigCROC Isolated Workspace Seeding (EXISTING_OC + UPGRADE) ──
// Writes to ~/.openclaw/agents/bigcroc/ — NEVER to workspace/ or agents/main/
// Satisfies INV-EU-3: BigCROC files isolated from user's agent files
function seedBigCROCWorkspaceIsolated() {
  var bigcrocPath = require("path").join(require("os").homedir(), ".openclaw", "agents", "bigcroc", "agent");
  try {
    var cur = fs.readFileSync(require("path").join(bigcrocPath, "SOUL.md"), "utf8");
    if (cur.includes("BigCROC")) {
      if (BIGCROC_WS.trust) {
        var trustPath = require("path").join(bigcrocPath, "Trust.md");
        if (!fs.existsSync(trustPath)) {
          fs.writeFileSync(trustPath, BIGCROC_WS.trust, "utf8");
          console.log("[CROCbox] Trust.md seeded on upgrade (isolated)");
        }
      }
      console.log("[CROCbox] BigCROC isolated workspace already seeded"); return;
    }
  } catch(e) {}
  try { fs.mkdirSync(bigcrocPath, { recursive: true }); } catch(e) {}
  fs.writeFileSync(require("path").join(bigcrocPath, "SOUL.md"), BIGCROC_WS.soul, "utf8");
  fs.writeFileSync(require("path").join(bigcrocPath, "IDENTITY.md"), BIGCROC_WS.identity, "utf8");
  fs.writeFileSync(require("path").join(bigcrocPath, "USER.md"), BIGCROC_WS.user, "utf8");
  fs.writeFileSync(require("path").join(bigcrocPath, "AGENTS.md"), BIGCROC_WS.agents, "utf8");
  if (BIGCROC_WS.trust) fs.writeFileSync(require("path").join(bigcrocPath, "Trust.md"), BIGCROC_WS.trust, "utf8");
  console.log("[CROCbox] BigCROC isolated workspace seeded at: " + bigcrocPath);
}
// ── Existing User Welcome Screen ────────────────────────────────
// Different from NHB welcome: no "setup" language, emphasizes non-invasive wrap
function showExistingUserWelcome() {
  return new Promise(function(resolve) {
    var { BrowserWindow } = require('electron');
    var welcomeWin = new BrowserWindow({
      width: 640, height: 520,
      resizable: false,
      titleBarStyle: 'hiddenInset',
      backgroundColor: '#1a1a1a',
      webPreferences: { nodeIntegration: false, contextIsolation: true }
    });
    var html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body { margin:0; padding:40px; background:#1a1a1a; color:#e0e0e0;
    font-family:-apple-system,system-ui,Helvetica,Arial,sans-serif;
    display:flex; flex-direction:column; align-items:center; justify-content:center;
    height:calc(100vh - 80px); text-align:center; }
  .shield { width:80px; height:80px; margin-bottom:24px; }
  h1 { font-size:24px; font-weight:500; margin:0 0 12px 0; color:#d4a017; }
  .subtitle { font-size:15px; color:#aaa; margin-bottom:28px; line-height:1.5; }
  .features { text-align:left; max-width:400px; margin-bottom:32px; }
  .feature { display:flex; align-items:flex-start; gap:12px; margin-bottom:14px; }
  .feature-icon { font-size:18px; flex-shrink:0; margin-top:1px; }
  .feature-text { font-size:13px; color:#ccc; line-height:1.4; }
  .feature-text strong { color:#e0e0e0; font-weight:500; }
  .note { font-size:11px; color:#888; margin-bottom:24px; max-width:380px; line-height:1.4; }
  button { padding:12px 36px; font-size:15px; font-weight:500;
    font-family:-apple-system,system-ui,Helvetica,Arial,sans-serif;
    background:#d4a017; color:#1a1a1a; border:none; border-radius:8px;
    cursor:pointer; transition:background 0.2s; }
  button:hover { background:#e0b030; }
</style></head><body>
  <svg class="shield" viewBox="0 0 100 120" xmlns="http://www.w3.org/2000/svg">
    <path d="M50 5 L90 25 L90 60 C90 85 70 105 50 115 C30 105 10 85 10 60 L10 25 Z"
      fill="#d4a01730" stroke="#d4a017" stroke-width="3"/>
    <text x="50" y="72" text-anchor="middle" font-size="36" fill="#d4a017"
      font-family="-apple-system,system-ui,Helvetica,Arial,sans-serif"
      font-weight="500">Y</text>
  </svg>
  <h1>CROCbox Detected Your OpenClaw</h1>
  <p class="subtitle">Adding the Agent Trust Layer to your existing installation.<br>Nothing will be changed.</p>
  <div class="features">
    <div class="feature">
      <span class="feature-icon">&#x1F6E1;</span>
      <span class="feature-text"><strong>Green Shield consent</strong> fires on every tool your AI uses. You decide what happens.</span>
    </div>
    <div class="feature">
      <span class="feature-icon">&#x1F4CB;</span>
      <span class="feature-text"><strong>Tamper-evident audit log</strong> records every decision with a SHA-256 hash chain.</span>
    </div>
    <div class="feature">
      <span class="feature-icon">&#x2705;</span>
      <span class="feature-text"><strong>Your config is untouched.</strong> Your model, API keys, workspace, and skills stay exactly as they are.</span>
    </div>
  </div>
  <p class="note">CROCbox adds a trust layer between you and your AI. It does not modify OpenClaw. To remove it, just delete CROCbox.app.</p>
  <button onclick="window.close()">See the Trust Layer</button>
</body></html>`;
    welcomeWin.loadURL('data:text/html;base64,' + Buffer.from(html).toString('base64'));
    welcomeWin.on('closed', function() { resolve(); });
  });
}
// ── Trust Network Indicator ─────────────────────────────────────
function injectTrustNetworkIndicator(win, status) {
  if (!win || win.isDestroyed()) return;
  // If trust bar is active, skip — trust bar shows network status
  win.webContents.executeJavaScript('!!document.getElementById("crocbox-trust-bar")').then(function(hasBar) {
    if (hasBar) { console.log('[CROCbox] Trust bar active — skipping legacy indicator'); return; }
  }).catch(function() {});
  // Legacy indicator for when trust bar hasn't loaded yet
  var color = status === 'enrolled' ? '#4CAF50' : status === 'local' ? '#d4a017' : '#888';
  var label = status === 'enrolled' ? 'Trust Network' : status === 'local' ? 'Local Mode' : 'Not Connected';
  var dot = status === 'enrolled' ? '\u2705' : status === 'local' ? '\uD83D\uDFE1' : '\u26AA';

  win.webContents.executeJavaScript(`
    (function() {
      var old = document.getElementById('crocbox-trust-indicator');
      if (old) old.remove();
      var el = document.createElement('div');
      el.id = 'crocbox-trust-indicator';
      el.style.cssText = 'position:fixed;top:8px;right:420px;z-index:999989;padding:3px 10px;border-radius:6px;background:rgba(0,0,0,0.6);border:1px solid ${color}40;display:flex;align-items:center;gap:5px;font-family:-apple-system,sans-serif;font-size:10px;color:${color};';
      el.innerHTML = '<span>${dot}</span><span>${label}</span>';
      if ('${status}' === 'local') { el.style.cursor = 'pointer'; el.title = 'Click to activate your CROCbox'; el.addEventListener('click', function() { if (window.crocbox && window.crocbox.activate) window.crocbox.activate(); }); }
      document.body.appendChild(el);
      // Hide if trust bar is active (trust bar shows this info)
      if (document.getElementById('crocbox-trust-bar')) { el.style.display = 'none'; }
      console.log('[CROCbox] Trust Network indicator: ${status}');
    })();
  `).catch(function() {});
}

// ── VE Startup Check ───────────────────────────────────────────
function writeVeAuditEntry(agentId) {
  try {
    var auditDir = require('path').join(process.env.HOME || '/tmp', 'opnli', 'crocbox', 'logs');
    if (!fs.existsSync(auditDir)) fs.mkdirSync(auditDir, { recursive: true });
    var auditPath = require('path').join(auditDir, 'crocbox-audit.jsonl');
    var prev = 'genesis';
    try { var lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n'); var last = JSON.parse(lines[lines.length - 1]); prev = last.hash || 'genesis'; } catch(e) {}
    var entry = { timestamp: new Date().toISOString(), action: 've-validation', target: 've-staging.opn.li', result: 'verified', reason: 've-status-check', detail: 'VE_AGENT_ID=' + agentId, shield: 'green' };
    var hashData = JSON.stringify(entry) + prev;
    entry.prev_hash = prev;
    entry.hash = require('crypto').createHash('sha256').update(hashData).digest('hex');
    fs.appendFileSync(auditPath, JSON.stringify(entry) + '\n');
    console.log('[CROCbox] VE validation audit entry written (hash=' + entry.hash.substring(0, 12) + '...)');
  } catch(e) {
    console.warn('[CROCbox] Failed to write VE audit entry: ' + e.message);
  }
}

async function checkVeEnrollment() {
  try {
    // If we have a saved agent_id, verify the VE still recognizes us
    if (veAgentId) {
      console.log('[CROCbox] VE: Checking enrollment for agent_id=' + veAgentId);
      try {
        var cardId = null;
        try {
          var envContent = fs.readFileSync(process.env.CROCBOX_ENV_PATH || '', 'utf8');
          var m = envContent.match(/VE_CARD_ID=(.+)/);
          if (m) cardId = m[1].trim();
        } catch(e) {}
        if (!cardId) cardId = 'card-unknown';
        var sid = 'startup-' + Date.now();
        var verifyResult = await veVerify('web_search', cardId, sid);
        if (verifyResult && (verifyResult.decision === 'approved' || verifyResult.decision === 'allow')) {
          veStatus = 'enrolled';
          console.log('[CROCbox] VE: Agent verified and active (id=' + veAgentId + ')');
          writeVeAuditEntry(veAgentId);
          return 'enrolled';
        } else if (verifyResult && verifyResult.decision === 'denied' && verifyResult.reason && verifyResult.reason.includes('not recognized')) {
          console.log('[CROCbox] VE: Agent not recognized — will attempt re-enrollment');
          // Fall through to enrollment below
        } else {
          // VE responded but denied for another reason (e.g., operation not allowed)
          // Agent IS enrolled, just this operation was denied — that's still enrolled
          veStatus = 'enrolled';
          console.log('[CROCbox] VE: Agent enrolled (verify returned: ' + (verifyResult.decision || 'unknown') + ')');
          writeVeAuditEntry(veAgentId);
          return 'enrolled';
        }
      } catch (verifyErr) {
        console.log('[CROCbox] VE: Verify check failed — ' + verifyErr.message);
        // Network error — VE unreachable, stay local
        veStatus = 'local';
        return 'local';
      }
    }
    // No saved agent_id, or agent not recognized — attempt enrollment
    console.log('[CROCbox] VE: Attempting enrollment...');
    try {
      var acctPath = require('path').join(require('os').homedir(), '.crocbox', 'account.json');
      var acct = JSON.parse(fs.readFileSync(acctPath, 'utf8'));
      var enrollId = acct.member_id || acct.account_id;
      if (enrollId) {
        var enrollResult = await veEnroll(enrollId, rentalSkiLevel);
        if (enrollResult && enrollResult.agent_id) {
          veStatus = 'enrolled';
          veAgentId = enrollResult.agent_id;
          acct.agent_id = enrollResult.agent_id;
          fs.writeFileSync(acctPath, JSON.stringify(acct, null, 2), 'utf8');
          console.log('[CROCbox] VE: Enrollment successful (agent_id=' + enrollResult.agent_id + ')');
          writeVeAuditEntry(enrollResult.agent_id);
          return 'enrolled';
        }
      } else {
        console.log('[CROCbox] VE: No member_id in account.json — cannot enroll');
      }
    } catch (enrollErr) {
      console.log('[CROCbox] VE: Enrollment failed — ' + enrollErr.message);
    }
    console.log('[CROCbox] VE: Running in local mode');
    veStatus = 'local';
    return 'local';
  } catch (err) {
    console.log('[CROCbox] VE: Startup check failed — ' + err.message + ' — running in local mode');
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
    const apiKey = url.searchParams.get('api_key');
    const provider = url.searchParams.get('provider') || 'anthropic';
    const accessToken = url.searchParams.get('access_token');
    const refreshToken = url.searchParams.get('refresh_token');
    const memberId = url.searchParams.get('member_id');
    const anonKey = url.searchParams.get('anon_key');
    if (accountId) {
      console.log('[CROCbox] Activation callback received: account_id=' + accountId + (apiKey ? ' with API key' : ' no API key'));
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body style="background:#1a1a1a;color:#ccc;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2 style="color:#d4a017">CROCbox Activated</h2><p>You can close this tab and return to CROCbox.</p></div></body></html>');
      // Complete enrollment
      completeActivation(win, accountId, email, apiKey, provider, accessToken, refreshToken, memberId, anonKey);
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

async function completeActivation(win, accountId, email, apiKey, provider, accessToken, refreshToken, memberId, anonKey) {
  // Step 1: Write account.json UNCONDITIONALLY (do not gate on VE enrollment)
  var statePath = require('path').join(require('os').homedir(), '.crocbox');
  try { fs.mkdirSync(statePath, { recursive: true }); } catch(e) {}
  var accountFile = require('path').join(statePath, 'account.json');
  fs.writeFileSync(accountFile,
    JSON.stringify({ account_id: accountId, email: email || '', activated: new Date().toISOString(), firstRun: true, access_token: accessToken || '', refresh_token: refreshToken || '', member_id: memberId || accountId, anon_key: anonKey || '' }, null, 2), 'utf8');
  console.log('[CROCbox] account.json written: ' + accountFile);

  // Step 1b: Write CROCBOX_MEMBER_ID to .env so Green Shield gate has it on next launch
  try {
    var envPath = process.env.CROCBOX_ENV_PATH || require("path").join(require("os").homedir(), "Library", "Application Support", "CROCbox", ".env");
    var envContent = "";
    try { envContent = fs.readFileSync(envPath, "utf8"); } catch(e) {}
    if (envContent.indexOf("CROCBOX_MEMBER_ID") === -1) {
      envContent += "\nCROCBOX_MEMBER_ID=" + (memberId || accountId) + "\n";
      fs.writeFileSync(envPath, envContent, "utf8");
      console.log("[CROCbox] CROCBOX_MEMBER_ID written to .env");
    } else {
      envContent = envContent.replace(/CROCBOX_MEMBER_ID=.*/, "CROCBOX_MEMBER_ID=" + (memberId || accountId));
      fs.writeFileSync(envPath, envContent, "utf8");
      console.log("[CROCbox] CROCBOX_MEMBER_ID updated in .env");
    }
    // CONSENT_SERVER_URL and CONSENT_SUBMIT_SECRET — written during activation so Green Shield gate connects
    if (envContent.indexOf("CONSENT_SERVER_URL") === -1) { envContent += "CONSENT_SERVER_URL=https://consent.opn.li\n"; }
    if (envContent.indexOf("CONSENT_SUBMIT_SECRET") === -1) { envContent += "CONSENT_SUBMIT_SECRET=07a1aaa6e0bb5e0347311f61387d40460140da5f5d1e0c705abad7a71254f849\n"; }
    fs.writeFileSync(envPath, envContent, "utf8");
    console.log("[CROCbox] .env written: MEMBER_ID + CONSENT_SERVER_URL + CONSENT_SUBMIT_SECRET");
  } catch(envErr) { console.log("[CROCbox] .env write failed: " + envErr.message); }

  // Step 2: Write API key UNCONDITIONALLY (do not gate on VE enrollment)
  if (apiKey) {
    var ocDir = require('path').join(process.env.HOME || '/tmp', '.openclaw');
    var authDir = require('path').join(ocDir, 'agents', 'main', 'agent');
    var authPath = require('path').join(authDir, 'auth-profiles.json');
    if (!fs.existsSync(authDir)) fs.mkdirSync(authDir, { recursive: true });
    var profiles = { version: 1, profiles: {}, usageStats: {} };
    try { profiles = JSON.parse(fs.readFileSync(authPath, 'utf8')); } catch(e) {}
    var label = provider + ':default';
    profiles.profiles[label] = { type: 'api_key', provider: provider, apiKey: apiKey, key: apiKey };
    // Fix 3: Bake Neurometric free-tier profile alongside activation-delivered key.
    // See completeActivation schema note: Anthropic uses type:'api_key'+apiKey, Neurometric uses type:'token'+token.
    profiles.profiles['neurometric:default'] = { type: 'token', provider: 'neurometric', token: 'mk_live_qcr1h31RTWZUZrhl5GfrbFSFXSxgQ7ec' };
    fs.writeFileSync(authPath, JSON.stringify(profiles, null, 2), 'utf8');
    console.log('[CROCbox] API key delivered via activation: ' + label);
    // Audit log
    try {
      var auditDir = require('path').join(process.env.HOME || '/tmp', 'opnli', 'crocbox', 'logs');
      if (!fs.existsSync(auditDir)) fs.mkdirSync(auditDir, { recursive: true });
      var auditPath = require('path').join(auditDir, 'crocbox-audit.jsonl');
      var prev = 'genesis';
      try { var lines = fs.readFileSync(auditPath,'utf8').trim().split('\n'); var last = JSON.parse(lines[lines.length-1]); prev = last.hash || 'genesis'; } catch(e) {}
      var entry = { timestamp: new Date().toISOString(), action: 'keycard-activation', target: label, result: 'stored', reason: 'activation-delivery', detail: 'API key delivered during CROCbox activation', shield: 'yellow' };
      var hashData = JSON.stringify(entry) + prev;
      entry.prev_hash = prev;
      entry.hash = require('crypto').createHash('sha256').update(hashData).digest('hex');
      fs.appendFileSync(auditPath, JSON.stringify(entry) + '\n');
    } catch(ae) {}
    // Fix 3: Audit entry for Neurometric bake (hash-chains from Anthropic entry above).
    try {
      var neuroEntry = { timestamp: new Date().toISOString(), action: 'keycard-activation', target: 'neurometric:default', result: 'stored', reason: 'neurometric-bake', detail: 'Neurometric free-tier key baked during CROCbox activation', shield: 'yellow' };
      var neuroPrev = entry.hash || 'genesis';
      var neuroHashData = JSON.stringify(neuroEntry) + neuroPrev;
      neuroEntry.prev_hash = neuroPrev;
      neuroEntry.hash = require('crypto').createHash('sha256').update(neuroHashData).digest('hex');
      fs.appendFileSync(auditPath, JSON.stringify(neuroEntry) + n);
    } catch(ae2) {}
  } else {
    console.log('[CROCbox] WARNING: No API key in activation callback — BigCROC will not be able to chat');
  }

  // Step 3: VE enrollment (separate, non-blocking for key delivery)
  try {
    console.log('[CROCbox] Enrolling with VE...');
    var result = await veEnroll(accountId, rentalSkiLevel);
    if (result && result.agent_id) {
      veStatus = 'enrolled';
      veAgentId = result.agent_id;
      console.log('[CROCbox] VE enrollment complete: agent_id=' + result.agent_id);
      // Update account.json with agent_id
      try {
        var acct = JSON.parse(fs.readFileSync(accountFile, 'utf8'));
        acct.agent_id = result.agent_id;
        fs.writeFileSync(accountFile, JSON.stringify(acct, null, 2), 'utf8');
      } catch(e) {}
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
    + '.title{font-size:16px;font-weight:500;color:#f0f0f0}'
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

// ── keyCARD — Multi-Provider API Key Management ─────────────────
function getConfiguredProviders() {
  var configPath = path.join(process.env.HOME || '/tmp', '.openclaw', 'openclaw.json');
  var keyPath = path.join(process.env.HOME || '/tmp', '.openclaw', 'agents', 'main', 'agent', 'auth-profiles.json');
  var providers = [];
  var activeModel = '';
  try {
    var config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    activeModel = (config.agents && config.agents.defaults && config.agents.defaults.model && config.agents.defaults.model.primary) || '';
  } catch(e) {}
  // Check Anthropic (built-in, key in auth-profiles)
  try {
    var profiles = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    var pkeys = Object.keys(profiles.profiles || {});
    for (var i = 0; i < pkeys.length; i++) {
      var pk = pkeys[i];
      var entry = profiles.profiles[pk];
      var raw = entry.apiKey || entry.key || entry.token || '';
      var masked = raw.length > 12 ? raw.substring(0, 8) + '...' + raw.substring(raw.length - 4) : (raw ? '(set)' : '(empty)');
      var prov = entry.provider || pk.split(':')[0] || 'unknown';
      var isActive = activeModel.indexOf(prov) === 0 || (prov === 'anthropic' && activeModel.indexOf('anthropic/') === 0);
      providers.push({ label: pk, provider: prov, maskedKey: masked, active: isActive });
    }
  } catch(e) {}
  return { providers: providers, activeModel: activeModel };
}

function openKeyCARDWindow() {
  var info = getConfiguredProviders();
  // Build provider rows HTML
  var providerRowsHTML = '';
  if (info.providers.length === 0) {
    providerRowsHTML = '<div style="color:#666;font-size:12px;padding:8px 0;">No providers configured</div>';
  } else {
    info.providers.forEach(function(p) {
      var dot = p.active ? '#4CAF50' : '#555';
      var tag = p.active ? ' <span style="color:#4CAF50;font-size:10px;">ACTIVE</span>' : '';
      providerRowsHTML += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #222;">'
        + '<div style="width:8px;height:8px;border-radius:50%;background:' + dot + ';flex-shrink:0;"></div>'
        + '<div style="flex:1;"><div style="font-size:12px;color:#ccc;">' + p.provider.charAt(0).toUpperCase() + p.provider.slice(1) + tag + '</div>'
        + '<div style="font-size:11px;color:#666;font-family:monospace;">' + p.maskedKey + '</div></div></div>';
    });
  }
  var activeModelDisplay = info.activeModel || '(default)';

  // Write a minimal preload for the keyCARD window
  var kcPreloadPath = path.join(require('os').tmpdir(), 'crocbox-keycard-preload.js');
  fs.writeFileSync(kcPreloadPath, [
    "const { contextBridge, ipcRenderer } = require('electron');",
    "contextBridge.exposeInMainWorld('keycard', {",
    "  saveProvider: function(data) { return ipcRenderer.invoke('crocbox:save-provider', data); },",
    "  switchProvider: function(model) { return ipcRenderer.invoke('crocbox:switch-model', model); }",
    "});"
  ].join('\n'), 'utf8');

  var providerOptions = [
    { name: 'Anthropic', id: 'anthropic', baseUrl: '', model: 'anthropic/claude-sonnet-4-6', keyPrefix: 'sk-ant-', hint: 'Built-in provider. No base URL needed.' },
    { name: 'Neurometric', id: 'neurometric', baseUrl: 'https://api.neurometric.ai/v1', model: 'neurometric/clawpack', keyPrefix: '', hint: 'Free: 100M tokens/month. marketplace.neurometric.ai/clawpack' },
    { name: 'OpenAI', id: 'openai', baseUrl: 'https://api.openai.com/v1', model: 'openai/gpt-4o', keyPrefix: 'sk-', hint: 'Requires OpenAI API key.' },
    { name: 'OpenRouter', id: 'openrouter', baseUrl: 'https://openrouter.ai/api/v1', model: 'openrouter/auto', keyPrefix: 'sk-or-', hint: 'Aggregates 200+ models. openrouter.ai' },
    { name: 'Custom', id: 'custom', baseUrl: '', model: '', keyPrefix: '', hint: 'Any OpenAI-compatible endpoint.' }
  ];

  var optionsHTML = providerOptions.map(function(p) {
    return '<option value="' + p.id + '">' + p.name + '</option>';
  }).join('');

  var providerDataJS = JSON.stringify(providerOptions);

  var html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>keyCARD</title>'
    + '<style>'
    + 'body{margin:0;padding:20px;background:#1a1a1a;color:#f0f0f0;font-family:-apple-system,sans-serif;overflow-y:auto;}'
    + 'h2{font-size:18px;font-weight:500;margin:0 0 2px 0;}'
    + '.sub{color:#888;font-size:12px;margin-bottom:14px;}'
    + '.section{margin-bottom:14px;}'
    + '.section-title{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;font-weight:600;}'
    + '.providers-list{background:#111;border:1px solid #333;border-radius:6px;padding:8px 12px;margin-bottom:6px;}'
    + '.active-model{font-size:11px;color:#4CAF50;font-family:monospace;margin-bottom:14px;}'
    + '.field{margin-bottom:10px;}'
    + 'label{display:block;font-size:11px;color:#999;margin-bottom:3px;font-weight:500;}'
    + 'select,input{width:100%;padding:8px 10px;background:#111;border:1px solid #333;border-radius:6px;color:#f0f0f0;font-size:13px;box-sizing:border-box;}'
    + 'select{font-family:-apple-system,sans-serif;} input{font-family:monospace;}'
    + 'select:focus,input:focus{outline:none;border-color:#4CAF50;}'
    + '.hint{font-size:11px;color:#666;margin-top:3px;}'
    + '.btn-row{display:flex;gap:8px;margin-top:12px;}'
    + '.btn{flex:1;padding:10px 16px;border:none;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;}'
    + '.btn-save{background:#2E7D32;color:#fff;}'
    + '.btn-save:hover{background:#388E3C;}'
    + '.btn-save:disabled{background:#333;color:#666;cursor:default;}'
    + '.btn-switch{background:#1565C0;color:#fff;}'
    + '.btn-switch:hover{background:#1976D2;}'
    + '.msg{text-align:center;font-size:12px;margin-top:8px;display:none;}'
    + '.msg-ok{color:#4CAF50;} .msg-err{color:#EF4444;} .msg-info{color:#2196F3;}'
    + '.footer{text-align:center;color:#555;font-size:10px;margin-top:14px;}'
    + '.divider{border-top:1px solid #333;margin:14px 0;}'
    + '</style></head><body>'
    + '<h2>keyCARD</h2>'
    + '<div class="sub">Manage AI providers for BigCROC</div>'

    // Configured Providers section
    + '<div class="section"><div class="section-title">Configured Providers</div>'
    + '<div class="providers-list">' + providerRowsHTML + '</div>'
    + '<div class="active-model">Active model: ' + activeModelDisplay + '</div></div>'

    + '<div class="divider"></div>'

    // Add / Update Provider section
    + '<div class="section"><div class="section-title">Add or Update Provider</div>'
    + '<div class="field"><label>Provider</label><select id="provider">' + optionsHTML + '</select></div>'
    + '<div class="field"><label>API Key</label><input type="text" id="apikey" placeholder="Paste your API key" autocomplete="off" spellcheck="false"></div>'
    + '<div class="field"><label>Base URL</label><input type="text" id="baseurl" placeholder="(built-in — no URL needed)"></div>'
    + '<div class="field"><label>Model ID</label><input type="text" id="modelid" value="anthropic/claude-sonnet-4-6"></div>'
    + '<div class="hint" id="provider-hint">Built-in provider. No base URL needed.</div>'
    + '</div>'

    + '<div class="btn-row">'
    + '<button class="btn btn-save" id="savebtn" disabled>Save Provider</button>'
    + '<button class="btn btn-switch" id="switchbtn" style="display:none;">Set as Active</button>'
    + '</div>'
    + '<div class="msg msg-ok" id="msg-ok">Provider saved. Restart CROCbox to apply.</div>'
    + '<div class="msg msg-err" id="msg-err">Save failed. Check console.</div>'
    + '<div class="msg msg-info" id="msg-switch">Active model switched. Restart CROCbox to apply.</div>'
    + '<div class="footer">CROCbox is the trust layer, not the model layer.<br>Your consent gate works the same regardless of provider.</div>'

    + '<script>'
    + 'var providers = ' + providerDataJS + ';'
    + 'var sel = document.getElementById("provider");'
    + 'var keyInput = document.getElementById("apikey");'
    + 'var urlInput = document.getElementById("baseurl");'
    + 'var modelInput = document.getElementById("modelid");'
    + 'var hintEl = document.getElementById("provider-hint");'
    + 'var saveBtn = document.getElementById("savebtn");'
    + 'var switchBtn = document.getElementById("switchbtn");'

    + 'function updateFields() {'
    + '  var id = sel.value;'
    + '  var p = providers.find(function(x){return x.id===id;});'
    + '  if(p){'
    + '    urlInput.value = p.baseUrl;'
    + '    modelInput.value = p.model;'
    + '    hintEl.textContent = p.hint;'
    + '    urlInput.placeholder = p.baseUrl ? p.baseUrl : "(built-in — no URL needed)";'
    + '    keyInput.placeholder = p.keyPrefix ? p.keyPrefix + "..." : "Paste your API key";'
    + '  }'
    + '  checkSave();'
    + '}'
    + 'function checkSave() {'
    + '  var hasKey = keyInput.value.trim().length >= 8;'
    + '  var hasModel = modelInput.value.trim().length > 0;'
    + '  saveBtn.disabled = !(hasKey && hasModel);'
    + '  document.getElementById("msg-ok").style.display="none";'
    + '  document.getElementById("msg-err").style.display="none";'
    + '  document.getElementById("msg-switch").style.display="none";'
    + '}'

    + 'sel.addEventListener("change", updateFields);'
    + 'keyInput.addEventListener("input", checkSave);'
    + 'modelInput.addEventListener("input", checkSave);'

    + 'saveBtn.addEventListener("click", function(){'
    + '  saveBtn.disabled=true; saveBtn.textContent="Saving...";'
    + '  var data = {'
    + '    provider: sel.value,'
    + '    apiKey: keyInput.value.trim(),'
    + '    baseUrl: urlInput.value.trim(),'
    + '    model: modelInput.value.trim(),'
    + '    setActive: true'
    + '  };'
    + '  window.keycard.saveProvider(data).then(function(r){'
    + '    if(r&&r.ok){'
    + '      document.getElementById("msg-ok").style.display="block";'
    + '      saveBtn.textContent="Saved";'
    + '      keyInput.value="";'
    + '    } else {'
    + '      document.getElementById("msg-err").style.display="block";'
    + '      saveBtn.textContent="Save Provider"; saveBtn.disabled=false;'
    + '    }'
    + '  }).catch(function(){'
    + '    document.getElementById("msg-err").style.display="block";'
    + '    saveBtn.textContent="Save Provider"; saveBtn.disabled=false;'
    + '  });'
    + '});'

    + '</script></body></html>';

  var kcWin = new BrowserWindow({
    width: 440, height: 620, title: 'keyCARD — CROCbox',
    backgroundColor: '#1a1a1a',
    resizable: false,
    webPreferences: { nodeIntegration: false, contextIsolation: true, preload: kcPreloadPath }
  });
  kcWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  kcWin.setMenuBarVisibility(false);
}

// ── Shield Score + Trust Bar IPC ────────────────────────────────
function computeAndInjectShield(win, catalogPayload) {
  var tools = parseCatalog(catalogPayload);
  if (tools.length === 0) {
    console.log('[CROCbox] Shield: No tools in catalog — skipping');
    return;
  }
  currentShieldScore = computeShieldScore(tools, greenShieldActive ? 'green' : 'yellow', 0);
  console.log('[CROCbox] Shield Score computed:');
  console.log('[CROCbox]   Color: ' + currentShieldScore.color.toUpperCase());
  console.log('[CROCbox]   OWASP: ' + currentShieldScore.owasp.classified + '/' + currentShieldScore.owasp.toolCount + ' classified');
  console.log('[CROCbox]   AWS Scope: ' + currentShieldScore.aws.scope + ' (' + currentShieldScore.aws.label + ')');
  console.log('[CROCbox]   Meta: ' + currentShieldScore.meta.config + (currentShieldScore.meta.hitlRequired ? ' — HITL mandatory' : ''));
  console.log('[CROCbox]   Catalog Hash: ' + currentShieldScore.catalogHash.substring(0, 16) + '...');
  // Send Trust Bar data via IPC — preload renders it
  if (win && !win.isDestroyed() && win.webContents) {
    var veIndicator = veStatus === 'enrolled' ? 'Trust Network' : 'Local Mode';
    win.webContents.send('crocbox:trust-bar', { score: currentShieldScore, veLabel: veIndicator, greenShield: greenShieldActive ? true : false });
    console.log('[CROCbox] Trust Bar data sent via IPC (color=' + currentShieldScore.color + ', greenShield=' + (greenShieldActive ? 'true' : 'false') + ')');
  }
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
  .step-num { width:28px; height:28px; border-radius:50%; background:#2E7D32; color:#fff;
              display:flex; align-items:center; justify-content:center; font-weight:700;
              font-size:14px; flex-shrink:0; }
  .step-text { font-size:14px; line-height:1.5; color:#ccc; padding-top:3px; }
  .step-text strong { color:#f0f0f0; }
  .btn-row { padding:24px 40px; display:flex; justify-content:center; -webkit-app-region:no-drag; }
  .btn { padding:14px 48px; border:none; border-radius:10px; font-size:16px; font-weight:500;
         cursor:pointer; background:#2E7D32; color:#fff; font-family:-apple-system,system-ui,Helvetica,Arial,sans-serif; }
  .btn:hover { background:#388E3C; }
  .footer { font-size:11px; color:#555; text-align:center; padding-bottom:16px; }
</style></head><body>
<div class="content">
  <div class="shield"><svg width="72" height="86" viewBox="0 0 100 120" style="display:inline-block"><path d="M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z" fill="#1B5E20" stroke="#2E7D32" stroke-width="1.5"/><path d="M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z" fill="#2E7D32"/><path d="M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z" fill="#4CAF50"/></svg></div>
  <h1>Your AI Is Ready</h1>
  <div class="subtitle">It asks before every action</div>
  <div class="steps">
    <div class="step"><div class="step-num">1</div>
      <div class="step-text"><strong>Your AI wants to act.</strong> Search the web, run commands, read files &#8212; real actions on your computer.</div></div>
    <div class="step"><div class="step-num">2</div>
      <div class="step-text"><strong>CROCbox asks you first.</strong> Every action is intercepted before it happens. The Green Shield appears.</div></div>
    <div class="step"><div class="step-num">3</div>
      <div class="step-text"><strong>You decide.</strong> Allow or block. Nothing happens without your approval.</div></div>
  </div>
</div>
<div class="btn-row"><button class="btn" onclick="window.close()">Get Started</button></div>
<div class="footer">My data + Your AI + My control = Living Intelligence</div>
</body></html>`;
    // Load welcome HTML via base64 data URI (avoids temp file encoding issues)
    var welcomeBase64 = Buffer.from(welcomeHTML, 'utf8').toString('base64');
    welcomeWin.loadURL('data:text/html;base64,' + welcomeBase64);
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
function createWindow(gatewayConnection, installScenario, gatewayToken) {
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
  var loadUrl = PROXY_URL;
  if (installScenario === 'EXISTING_OC' && gatewayToken) {
    loadUrl = PROXY_URL + '/#token=' + gatewayToken;
    console.log('[CROCbox] Loading Control UI from ' + PROXY_URL + ' with token fragment (existing user)');
  } else {
    console.log('[CROCbox] Loading Control UI from ' + PROXY_URL + ' (via proxy)');
  }
  win.loadURL(loadUrl);
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
//
// The proxy detects a seq-gap (tool execution) and calls the IPC
// callback. main.js forwards the consent request to the renderer
// via webContents.send. The renderer shows the consent card and
// sends the decision back via ipcMain.handle.
//
// Flow:
// ── IPC Handlers (Controls Panel + Green Shield support) ─────
function registerIPC(win) {
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

  // Shield Scoring Engine IPC — click handler
  ipcMain.handle('crocbox:shield-detail', function() {
    if (!currentShieldScore) return '<div style="padding:24px;color:#888">Shield score not yet computed.</div>';
    return getShieldDetailHTML(currentShieldScore, rentalSkiLevel);
  });

  // ── Controls Panel IPC handlers ──────────────────────────────
  ipcMain.handle('crocbox:open-keycard', function() {
    openKeyCARDWindow();
    return true;
  });
  ipcMain.handle('crocbox:open-trust-model', function() {
    var trustPath = path.join(process.env.HOME || '/tmp', 'opnli', 'crocbox', 'Trust.md');
    if (fs.existsSync(trustPath)) {
      require('electron').shell.openPath(trustPath);
    } else {
      require('electron').dialog.showMessageBoxSync({ type: 'info', title: 'Trust Model', message: 'Trust.md not found. It will be created on next launch.' });
    }
    return true;
  });
  ipcMain.handle('crocbox:open-about', function() {
    require('electron').dialog.showMessageBoxSync({
      type: 'info',
      title: 'About CROCbox',
      message: 'CROCbox v1.0.0-beta.14',
      detail: 'The Agent Trust Layer for OpenClaw\n\nMy data + Your AI + My control = Living Intelligence\n\n© 2026 Openly Personal Networks, Inc. (Opn.li)\nhttps://opn.li'
    });
    return true;
  });
  // ── Multi-provider save handler ──
  ipcMain.handle('crocbox:save-provider', function(_event, data) {
    console.log('[CROCbox] keyCARD: saving provider=' + data.provider + ' model=' + data.model);
    try {
      var keyPath = path.join(process.env.HOME || '/tmp', '.openclaw', 'agents', 'main', 'agent', 'auth-profiles.json');
      var configPath = path.join(process.env.HOME || '/tmp', '.openclaw', 'openclaw.json');

      // 1. Save API key to auth-profiles.json
      var profiles = { profiles: {} };
      try { profiles = JSON.parse(fs.readFileSync(keyPath, 'utf8')); } catch(e) {}
      if (!profiles.profiles) profiles.profiles = {};
      var profileLabel = data.provider + ':default';
      if (data.provider === 'anthropic') {
        profiles.profiles[profileLabel] = { type: 'api_key', provider: 'anthropic', apiKey: data.apiKey, key: data.apiKey };
      } else {
        profiles.profiles[profileLabel] = { type: 'token', provider: data.provider, token: data.apiKey };
      }
      var keyDir = path.dirname(keyPath);
      if (!fs.existsSync(keyDir)) fs.mkdirSync(keyDir, { recursive: true });
      fs.writeFileSync(keyPath, JSON.stringify(profiles, null, 2), 'utf8');
      console.log('[CROCbox] keyCARD: auth-profiles updated for ' + profileLabel);

      // 2. Write provider config to openclaw.json (non-Anthropic providers need models.providers entry)
      var config = {};
      try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {}
      if (data.provider !== 'anthropic' && data.baseUrl) {
        if (!config.models) config.models = { mode: 'merge', providers: {} };
        if (!config.models.providers) config.models.providers = {};
        config.models.providers[data.provider] = {
          baseUrl: data.baseUrl,
          apiKey: data.apiKey,
          api: 'openai-completions',
          models: [{
            id: data.model,
            name: data.provider.charAt(0).toUpperCase() + data.provider.slice(1) + ' (' + data.model.split('/').pop() + ')',
            reasoning: false,
            input: ['text'],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 32000,
            maxTokens: 8000
          }]
        };
        console.log('[CROCbox] keyCARD: models.providers.' + data.provider + ' written to openclaw.json');
      }

      // 3. Set as active model if requested
      if (data.setActive && data.model) {
        if (!config.agents) config.agents = { defaults: { model: {} } };
        if (!config.agents.defaults) config.agents.defaults = { model: {} };
        if (!config.agents.defaults.model) config.agents.defaults.model = {};
        config.agents.defaults.model.primary = data.model;
        console.log('[CROCbox] keyCARD: active model set to ' + data.model);
      }

      // 4. Update meta timestamp
      if (!config.meta) config.meta = {};
      config.meta.lastTouchedAt = new Date().toISOString();

      fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
      console.log('[CROCbox] keyCARD: openclaw.json updated');

      return { ok: true };
    } catch(err) {
      console.log('[CROCbox] keyCARD: save failed — ' + err.message);
      return { ok: false, error: err.message };
    }
  });

  // ── Model switch handler (switch without re-entering key) ──
  ipcMain.handle('crocbox:switch-model', function(_event, model) {
    console.log('[CROCbox] Model switch: ' + model);
    try {
      var configPath = path.join(process.env.HOME || '/tmp', '.openclaw', 'openclaw.json');
      var config = {};
      try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {}
      if (!config.agents) config.agents = { defaults: { model: {} } };
      if (!config.agents.defaults) config.agents.defaults = { model: {} };
      if (!config.agents.defaults.model) config.agents.defaults.model = {};
      config.agents.defaults.model.primary = model;
      if (!config.meta) config.meta = {};
      config.meta.lastTouchedAt = new Date().toISOString();
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
      console.log('[CROCbox] Model switch: active model set to ' + model);
      return { ok: true };
    } catch(err) {
      console.log('[CROCbox] Model switch failed: ' + err.message);
      return { ok: false, error: err.message };
    }
  });
  // ── Switch Model Picker ──
  ipcMain.handle('crocbox:switch-model-picker', function() {
    var info = getConfiguredProviders();
    if (info.providers.length === 0) {
      require('electron').dialog.showMessageBoxSync({
        type: 'info', title: 'Switch Model',
        message: 'No providers configured.',
        detail: 'Open keyCARD to add a provider first.'
      });
      return true;
    }
    var choices = info.providers.map(function(p) {
      return p.provider.charAt(0).toUpperCase() + p.provider.slice(1) + (p.active ? ' (active)' : '');
    });
    var result = require('electron').dialog.showMessageBoxSync({
      type: 'question', title: 'Switch Model',
      message: 'Select active AI provider:',
      detail: 'Current: ' + (info.activeModel || '(default)') + '\n\nRestart CROCbox after switching.',
      buttons: choices.concat(['Cancel']),
      defaultId: choices.length,
      cancelId: choices.length
    });
    if (result < info.providers.length) {
      var selected = info.providers[result];
      // Look up the model for this provider from openclaw.json
      var configPath = path.join(process.env.HOME || '/tmp', '.openclaw', 'openclaw.json');
      var config = {};
      try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {}
      var model = '';
      if (selected.provider === 'anthropic') {
        model = 'anthropic/claude-sonnet-4-6';
      } else if (config.models && config.models.providers && config.models.providers[selected.provider]) {
        var pm = config.models.providers[selected.provider].models;
        if (pm && pm.length > 0) model = pm[0].id;
      }
      if (model) {
        if (!config.agents) config.agents = { defaults: { model: {} } };
        if (!config.agents.defaults) config.agents.defaults = { model: {} };
        if (!config.agents.defaults.model) config.agents.defaults.model = {};
        config.agents.defaults.model.primary = model;
        if (!config.meta) config.meta = {};
        config.meta.lastTouchedAt = new Date().toISOString();
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
        console.log('[CROCbox] Model switched to ' + model + ' (provider: ' + selected.provider + ')');
        require('electron').dialog.showMessageBoxSync({
          type: 'info', title: 'Model Switched',
          message: 'Active model: ' + model,
          detail: 'Restart CROCbox to use the new provider.'
        });
      }
    }
    return true;
  });

  console.log('[CROCbox] Controls panel IPC wired ✓');
  console.log('[CROCbox] Controls panel IPC wired \u2713');
}
// ── Application lifecycle ──────────────────────────────────────
let mainWindow = null;
const BIGCROC_WS = require('./bigcroc-workspace');
let gatewayConnection = null;
let gatewayToken = null;
let proxyServer = null;
let startupComplete = false; // Prevents premature quit during welcome screen
let installScenario = null; // Installation scenario: NHB | EXISTING_OC | UPGRADE
let currentShieldScore = null; // Shield Scoring Engine state
let rentalSkiLevel = 'beginner'; // Default Rental Ski level
let veStatus = 'unknown'; // Trust Network status: enrolled, local, error
let veAgentId = null; // VE agent ID (from enrollment)
app.whenReady().then(async () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   CROCbox v1.0.0-beta.14 — Green Shield       ║');
  console.log('  ║   The Agent Trust Layer for OpenClaw  ║');
  console.log('  ║   Shield Scoring Engine Edition       ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  // Step -1: Clean orphan CROCbox processes holding our ports
  (function cleanOrphanProcesses() {
    var portsToCheck = [18788, 18793];
    var execSync = require("child_process").execSync;
    portsToCheck.forEach(function(port) {
      try {
        var pids = execSync("lsof -ti :" + port, { encoding: "utf8" }).trim();
        if (!pids) return;
        pids.split("\n").forEach(function(pid) {
          pid = pid.trim();
          if (!pid || pid === String(process.pid)) return;
          try {
            var cmdline = execSync("ps -p " + pid + " -o comm=", { encoding: "utf8" }).trim();
            if (cmdline.includes("CROCbox") || cmdline.includes("Electron") || cmdline.includes("electron")) {
              console.log("[CROCbox] Orphan process found: PID " + pid + " (" + cmdline + ") on port " + port + " — sending SIGTERM");
              try { process.kill(Number(pid), "SIGTERM"); } catch(e) {}
              // Wait up to 5 seconds for graceful shutdown
              var waited = 0;
              while (waited < 5000) {
                try { process.kill(Number(pid), 0); } catch(e) { break; }
                execSync("sleep 0.5");
                waited += 500;
              }
              // If still alive, SIGKILL
              try {
                process.kill(Number(pid), 0);
                console.log("[CROCbox] Orphan PID " + pid + " still alive after 5s — sending SIGKILL");
                try { process.kill(Number(pid), "SIGKILL"); } catch(e) {}
              } catch(e) {
                console.log("[CROCbox] Orphan PID " + pid + " terminated gracefully");
              }
            } else {
              console.log("[CROCbox] Port " + port + " held by non-CROCbox process: " + cmdline + " (PID " + pid + ")");
              dialog.showMessageBoxSync({
                type: "warning",
                title: "CROCbox — Port In Use",
                message: "Port " + port + " is in use by " + cmdline + ".",
                detail: "Please close that application and relaunch CROCbox.",
                buttons: ["OK"]
              });
            }
          } catch(e) {}
        });
      } catch(e) {
        // lsof returns non-zero if no process found — that is fine
      }
    });
    console.log("[CROCbox] Orphan process check complete");
  })();

  // Step 0: Detect OpenClaw — system or bundled
  var useSystemOC = detectOpenClaw();
  // Step 0.5: Classify installation scenario (INV-DK-1)
  installScenario = classifyInstallation();
  console.log('[CROCbox] Scenario: ' + installScenario);
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
    // EXISTING_OC should never reach here (useSystemOC would be true)
    // But guard anyway for safety (INV-EU-6)
    if (installScenario === 'EXISTING_OC') {
      console.error('[CROCbox] ERROR: EXISTING_OC but no system OpenClaw — falling back to NHB');
      installScenario = 'NHB';
    }
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
  // EXISTING_OC/UPGRADE: Read config without writing (INV-EU-1, INV-EU-4)
  if (installScenario === 'EXISTING_OC' || installScenario === 'UPGRADE') {
    console.log('[CROCbox] Existing installation — reading config (read-only mode)');
    var ocConfigPath = require('path').join(process.env.HOME || '/tmp', '.openclaw', 'openclaw.json');
    try {
      var existingConfig = JSON.parse(fs.readFileSync(ocConfigPath, 'utf8'));
      console.log('[CROCbox]   Gateway token: ' + (existingConfig.gateway?.auth?.token ? 'present \u2713' : 'MISSING'));
      console.log('[CROCbox]   Model: ' + (existingConfig.agents?.defaults?.model?.primary || 'default') + ' (not modified)');
    } catch (e) {
      console.log('[CROCbox]   Could not read existing config: ' + e.message);
    // Fix 4: Stale state protection - check auth-profiles.json exists
    var authProfilesPath = require('path').join(process.env.HOME || '/tmp', '.openclaw', 'agents', 'main', 'agent', 'auth-profiles.json');
    if (!fs.existsSync(authProfilesPath)) {
      console.log('[CROCbox] WARNING: launched marker exists but auth-profiles.json missing. Re-triggering activation flow.');
      fs.unlinkSync(require('path').join(process.env.HOME || '/tmp', '.crocbox', 'launched'));
      installScenario = 'NHB';
      console.log('[CROCbox] Classification changed to NHB - activation required');
    }
    }
  }
  console.log('[CROCbox] OpenClaw: ' + (useSystemOC ? 'system' : 'bundled') + ' \u2713');

  // Step 1: Read auth token
  gatewayToken = readGatewayToken();
  if (!gatewayToken) {
    if (!useSystemOC && bundled.bundled && installScenario === 'NHB') {
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

  // Step 4: Start the HTTP+WS Proxy (A.7 + A.8)
  var deviceId = getCROCboxDeviceId();
  try {
    proxyServer = await startProxy({ token: gatewayToken, deviceId: deviceId, scenario: installScenario });
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
  if (installScenario === 'EXISTING_OC') {
    seedBigCROCWorkspaceIsolated();
  } else if (installScenario === 'UPGRADE') {
    // On upgrade, only seed if BigCROC files don't exist yet
    seedBigCROCWorkspaceIsolated();
  } else {
    seedBigCROCWorkspace();
  }
  // Step 5: First-launch welcome screen (OB-1)
  ensureStateDir();
  ensureTrustMd();
  var firstLaunch = isFirstLaunch();
  // EXISTING_OC: Never run activation — user has their own API keys (INV-EU-2)
  if (installScenario === 'EXISTING_OC' && firstLaunch) {
    console.log('[CROCbox] Existing OpenClaw user — skipping NHB activation');
    console.log('[CROCbox] Showing Existing User welcome screen...');
    await showExistingUserWelcome();
    markLaunched();
    console.log('[CROCbox] Existing User welcome completed \u2713');
    firstLaunch = false; // Skip the NHB first-launch block below
  }
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
          const apiKey = url.searchParams.get('api_key');
          const provider = url.searchParams.get('provider') || 'anthropic';
          const accessToken = url.searchParams.get('access_token');
          const refreshToken = url.searchParams.get('refresh_token');
          const memberId = url.searchParams.get('member_id');
          const anonKey = url.searchParams.get('anon_key');
          if (accountId) {
            console.log('[CROCbox] Activation callback received: account_id=' + accountId + (apiKey ? ' with API key' : ' no API key'));
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body style="background:#1a1a1a;color:#ccc;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2 style="color:#d4a017">CROCbox Activated</h2><p>You can close this tab and return to CROCbox.</p></div></body></html>');
            // Save account and enroll
            completeActivation(null, accountId, email, apiKey, provider, accessToken, refreshToken, memberId, anonKey).then(() => {
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
      // Re-initialize Agent Sync now that account.json has auth credentials
      try { agentSync.init({ agent_name: 'BigCROC', model: 'anthropic/claude-sonnet-4-6', shield_level: 'green', skill_count: 0 }); console.log('[CROCbox] Agent Sync re-initialized after activation (enabled=' + agentSync.isEnabled() + ')'); } catch(e) { console.warn('[CROCbox] Agent Sync re-init failed:', e.message); }
      // B4: Restart Gateway so it reads the new auth-profiles.json
      if (bundledGatewayProcess) {
        console.log('[CROCbox] Restarting Gateway to load API key...');
        try { bundledGatewayProcess.kill(); } catch(e) {}
        bundledGatewayProcess = null;
        await new Promise(r => setTimeout(r, 2000));
        var restartPaths = getBundledPaths();
        if (restartPaths.bundled && restartPaths.extracted) {
          await startBundledGateway(restartPaths);
          console.log('[CROCbox] Gateway restarted with API key');
          // B4b: Reconnect main process WebSocket to new Gateway
          try {
            gatewayConnection = await connectToGateway(gatewayToken);
            console.log('[CROCbox] WebSocket reconnected after Gateway restart');
          } catch(reconErr) {
            console.log('[CROCbox] WebSocket reconnect failed: ' + reconErr.message);
          }
        }
      }
    } catch (err) {
      console.log('[CROCbox] Account activation skipped: ' + err.message);
    }
  }

  // Step 6: Create the application window
  mainWindow = createWindow(gatewayConnection, installScenario, gatewayToken);
  console.log('[CROCbox] Application window created ✓');

  // Step 7: Register IPC handlers
  registerIPC(mainWindow);
  // Step 7b: Start Green Shield consent server (CBE — Consent Before Execution)
  startGreenShieldServer();
  // Step 7c: Initialize Agent Sync (forwards consent decisions to opn.li
  // Supabase). Runs AFTER the gate is up and BEFORE any consent card can
  // fire. Disables itself cleanly if account.json is absent (Local Mode).
  try {
    agentSync.init({
      agent_name: 'BigCROC',
      model: 'anthropic/claude-sonnet-4-6',
      shield_level: 'green',
      skill_count: 0
    });
    console.log('[CROCbox] Agent Sync initialized (enabled=' + agentSync.isEnabled() + ')');
  } catch (e) {
    console.warn('[CROCbox] Agent Sync init error (non-fatal):', e.message);
  }
  setConsentCallback(function(consentData) {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      console.log('[CROCbox] Green Shield: forwarding consent request to renderer via IPC (tool=' + consentData.toolName + ')');
      mainWindow.webContents.send('crocbox:green-consent-request', consentData);
    } else {
      console.log('[CROCbox] Green Shield: window not available — tool will be blocked (fail-closed)');
    }
  });
  // Handle Green Shield timeout notification to renderer
  setTimeoutCallback(function(timeoutData) {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      console.log('[CROCbox] Green Shield: timeout notification to renderer (tool=' + timeoutData.toolName + ' id=' + timeoutData.requestId + ')');
      mainWindow.webContents.send('crocbox:green-consent-timeout', timeoutData);
    }
  });
  // RE-1: Handle Green Shield chain receipt (or NOT RECORDED notice) to renderer
  setReceiptCallback(function(receiptData) {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      console.log('[CROCbox] Green Shield: receipt to renderer (recorded=' + receiptData.recorded + ' id=' + receiptData.requestId + ')');
      mainWindow.webContents.send('crocbox:green-consent-receipt', receiptData);
    } else {
      console.error('[CROCbox] Green Shield: window gone — receipt not shown (recorded=' + receiptData.recorded + ')');
    }
  });

  // Step 5: a standing rule already decided — show the receipt, skip the question
  setRuleAppliedCallback(function(ruleData) {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      console.log('[CROCbox] Green Shield: rule applied to renderer (decision=' + ruleData.decision +
                  ' rule=' + ruleData.rule_id + ')');
      mainWindow.webContents.send('crocbox:green-consent-rule-applied', ruleData);
    } else {
      console.error('[CROCbox] Green Shield: window gone — rule receipt not shown');
    }
  });

  // Handle Green Shield consent decisions from renderer (A.12)
  ipcMain.handle('crocbox:green-consent-resolve', function(_event, requestId, decision) {
    console.log('[CROCbox] Green Shield IPC: received decision from renderer — requestId=' + requestId + ' decision=' + decision);
    return resolveGreenConsent(requestId, decision);
  });

  // S3: List active rules for the Review Rules panel
  ipcMain.handle('crocbox:list-rules', function() {
    return new Promise(function(resolve) {
      var CONSENT_SERVER_URL = process.env.CONSENT_SERVER_URL || '';
      var CONSENT_SUBMIT_SECRET = process.env.CONSENT_SUBMIT_SECRET || '';
      if (!CONSENT_SERVER_URL || !CONSENT_SUBMIT_SECRET) {
        resolve({ ok: false, error: 'No consent server credentials' });
        return;
      }
      var url = new (require('url').URL)(CONSENT_SERVER_URL + '/v1/rules/list');
      var https = require('https');
      var req = https.request({
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET },
        timeout: 10000
      }, function(res) {
        var body = '';
        res.on('data', function(chunk) { body += chunk; });
        res.on('end', function() {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            resolve({ ok: false, error: 'Bad response' });
          }
        });
      });
      req.on('error', function(err) { resolve({ ok: false, error: err.message }); });
      req.on('timeout', function() { req.destroy(); resolve({ ok: false, error: 'Timed out' }); });
      req.end();
    });
  });

  // S3: Revoke a rule from the Review Rules panel
  ipcMain.handle('crocbox:revoke-rule', function(_event, ruleId) {
    return new Promise(function(resolve) {
      var CONSENT_SERVER_URL = process.env.CONSENT_SERVER_URL || '';
      var CONSENT_SUBMIT_SECRET = process.env.CONSENT_SUBMIT_SECRET || '';
      if (!CONSENT_SERVER_URL || !CONSENT_SUBMIT_SECRET) {
        resolve({ ok: false, error: 'No consent server credentials' });
        return;
      }
      var payload = JSON.stringify({ rule_id: ruleId });
      var url = new (require('url').URL)(CONSENT_SERVER_URL + '/v1/rules/revoke');
      var https = require('https');
      var req = https.request({
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET,
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 10000
      }, function(res) {
        var body = '';
        res.on('data', function(chunk) { body += chunk; });
        res.on('end', function() {
          try {
            var result = JSON.parse(body);
            console.log('[CROCbox] revoke-rule: ' + (result.ok ? 'revoked ' + ruleId : 'failed'));
            resolve(result);
          } catch (e) {
            resolve({ ok: false, error: 'Bad response' });
          }
        });
      });
      req.on('error', function(err) { resolve({ ok: false, error: err.message }); });
      req.on('timeout', function() { req.destroy(); resolve({ ok: false, error: 'Timed out' }); });
      req.write(payload);
      req.end();
    });
  });

  // S3: Open My Rules panel in the renderer
  ipcMain.handle('crocbox:open-my-rules', function() {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
      mainWindow.webContents.send('crocbox:open-my-rules');
    }
  });

  // S3: Create a standing rule from the five-choice card
  ipcMain.handle('crocbox:create-rule', function(_event, ruleData) {
    return new Promise(function(resolve) {
      var CONSENT_SERVER_URL = process.env.CONSENT_SERVER_URL || '';
      var CONSENT_SUBMIT_SECRET = process.env.CONSENT_SUBMIT_SECRET || '';

      if (!CONSENT_SERVER_URL || !CONSENT_SUBMIT_SECRET) {
        console.error('[CROCbox] create-rule: no consent server credentials');
        resolve({ ok: false, error: 'No consent server credentials' });
        return;
      }

      var payload = JSON.stringify({
        action_type: ruleData.action_type,
        decision: ruleData.decision,
        rule_sentence: ruleData.rule_sentence,
        expires_at: ruleData.expires_at || undefined
      });

      var url = new (require('url').URL)(CONSENT_SERVER_URL + '/v1/rules/create');
      var https = require('https');

      var req = https.request({
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET,
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 10000
      }, function(res) {
        var body = '';
        res.on('data', function(chunk) { body += chunk; });
        res.on('end', function() {
          try {
            var result = JSON.parse(body);
            if (res.statusCode >= 200 && res.statusCode < 300 && !result.error) {
              console.log('[CROCbox] create-rule: rule created — ' + (result.rule_id || 'ok'));
              resolve({ ok: true, rule_id: result.rule_id || null });
            } else {
              console.error('[CROCbox] create-rule: server returned — ' + body.substring(0, 200));
              resolve({ ok: false, error: result.error || ('HTTP ' + res.statusCode) });
            }
          } catch (e) {
            console.error('[CROCbox] create-rule: bad response — ' + body.substring(0, 200));
            resolve({ ok: false, error: 'Bad response from consent server' });
          }
        });
      });

      req.on('error', function(err) {
        console.error('[CROCbox] create-rule: request failed — ' + err.message);
        resolve({ ok: false, error: 'Could not reach consent server' });
      });

      req.on('timeout', function() {
        req.destroy();
        console.error('[CROCbox] create-rule: timed out');
        resolve({ ok: false, error: 'Consent server timed out' });
      });

      req.write(payload);
      req.end();
    });
  });
  setGreenShieldActive(true);
  greenShieldActive = true;
  console.log('[CROCbox] Green Shield consent server started ✓');

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
  } catch (e) {
    // No saved account — auto-launch activation flow
    console.log("[CROCbox] No account.json found — launching activation flow");
    startActivationFlow(mainWindow);
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
  console.log('[CROCbox] ✓ CROCbox v1.0.0-beta.14 ready');
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
    mainWindow = createWindow(gatewayConnection, installScenario, gatewayToken);
  }
});
