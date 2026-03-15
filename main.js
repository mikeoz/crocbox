/**
 * CROCbox v0.8 — Electron Main Process
 * 
 * Phase 1: Gateway Connection
 * 
 * This is the entry point for the CROCbox Electron application.
 * It verifies the OpenClaw Gateway is running, connects via WebSocket,
 * and loads the Control UI in a BrowserWindow.
 * 
 * Architecture:
 *   Electron Main Process
 *     ├── Gateway health check (is OpenClaw running?)
 *     ├── WebSocket connection (gateway-client, token auth)
 *     ├── BrowserWindow (loads Control UI from Gateway)
 *     └── [Phase 4: CARD Proxy WebSocket MITM — not yet]
 * 
 * @see OPN_ENG_v08-Architecture_15MAR26_v1, Section 3.2
 */

const { app, BrowserWindow } = require('electron');
const { execSync } = require('child_process');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');

// ── Configuration ──────────────────────────────────────────────
const GATEWAY_PORT = 18789;
const GATEWAY_HOST = '127.0.0.1';
const GATEWAY_URL = `http://${GATEWAY_HOST}:${GATEWAY_PORT}`;
const GATEWAY_WS = `ws://${GATEWAY_HOST}:${GATEWAY_PORT}`;

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

      // Handle challenge-nonce handshake
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

      // Handle connect response
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

  // Load the OpenClaw Control UI directly from the Gateway
  console.log('[CROCbox] Loading Control UI from ' + GATEWAY_URL);
  win.loadURL(GATEWAY_URL);

  win.webContents.on('did-finish-load', () => {
    console.log('[CROCbox] Control UI loaded in BrowserWindow');
    // Inject CROCbox title bar identifier
    win.webContents.executeJavaScript(`
      document.title = 'CROCbox — Your AI, Your Control';
    `).catch(() => {});
  });

  win.on('closed', () => {
    // Clean up Gateway WebSocket
    if (gatewayConnection && gatewayConnection.ws) {
      gatewayConnection.ws.close();
    }
  });

  return win;
}

// ── Application lifecycle ──────────────────────────────────────
let mainWindow = null;
let gatewayConnection = null;

app.whenReady().then(async () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log('  ║   CROCbox v0.8.0 — Soft Launch       ║');
  console.log('  ║   The Agent Trust Layer for OpenClaw  ║');
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');

  // Step 1: Read auth token
  const token = readGatewayToken();
  if (!token) {
    console.error('[CROCbox] FATAL: No Gateway auth token found in ~/.openclaw/openclaw.json');
    console.error('[CROCbox] Run "openclaw" first to set up OpenClaw.');
    app.quit();
    return;
  }
  console.log('[CROCbox] Auth token loaded from openclaw.json');

  // Step 2: Check Gateway is running
  console.log('[CROCbox] Checking Gateway at ' + GATEWAY_URL + '...');
  const running = await checkGatewayRunning();
  if (!running) {
    console.error('[CROCbox] FATAL: OpenClaw Gateway not running on port ' + GATEWAY_PORT);
    console.error('[CROCbox] Start it with: openclaw');
    app.quit();
    return;
  }
  console.log('[CROCbox] Gateway is running ✓');

  // Step 3: Connect via WebSocket
  try {
    gatewayConnection = await connectToGateway(token);
    console.log('[CROCbox] Gateway connection established ✓');
  } catch (err) {
    console.error('[CROCbox] FATAL: ' + err.message);
    app.quit();
    return;
  }

  // Step 4: Create the application window
  mainWindow = createWindow(gatewayConnection);
  console.log('[CROCbox] Application window created ✓');
  console.log('');
});

app.on('window-all-closed', () => {
  if (gatewayConnection && gatewayConnection.ws) {
    gatewayConnection.ws.close();
  }
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0 && gatewayConnection) {
    mainWindow = createWindow(gatewayConnection);
  }
});
