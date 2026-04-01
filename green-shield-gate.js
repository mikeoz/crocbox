/**
 * green-shield-gate.js — Green Shield Consent Gate for CROCbox
 * 
 * This module provides a local HTTP consent server that the modified
 * before_tool_call hook in the bundled OpenClaw agent runtime calls
 * before executing ANY tool.
 * 
 * Architecture:
 *   Agent runtime (before_tool_call hook)
 *     -> HTTP POST http://127.0.0.1:{port}/green-shield-consent
 *       -> main.js renders Green Shield consent card
 *         -> NHB clicks Allow or Block (or timeout)
 *           -> HTTP response returns { allowed: true/false }
 *             -> Hook proceeds or throws error
 * 
 * The HTTP request BLOCKS until the NHB decides. This is the key
 * difference from Yellow Shield: the tool has NOT executed yet.
 * 
 * Fail-closed: If the server is not running, the HTTP request fails,
 * and the hook blocks the tool.
 */

const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ── Configuration ──────────────────────────────────────────────
const GREEN_SHIELD_PORT = 18793;
const CONSENT_TIMEOUT_MS = 60000; // 60 seconds, same as Yellow Shield

// ── State ──────────────────────────────────────────────────────
// Pending consent requests. Key: requestId, Value: { resolve, timer, toolName, params }
const pendingGreenConsents = new Map();

// Reference to the Electron BrowserWindow (set by main.js)
let mainWindow = null;

// ── Audit Logger ───────────────────────────────────────────────
const AUDIT_LOG_PATH = path.join(
  process.env.HOME || '/tmp', 'opnli', 'crocbox', 'logs', 'crocbox-audit.jsonl'
);

function writeGreenShieldAudit(requestId, toolName, decision, params) {
  try {
    var prevHash = 'genesis';
    try {
      var lines = fs.readFileSync(AUDIT_LOG_PATH, 'utf8').trim().split('\n');
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
      action: 'green-shield',
      target: toolName || 'unknown-tool',
      result: resultMap[decision] || 'blocked',
      reason: reasonMap[decision] || 'unknown',
      detail: 'tool=' + toolName + ' requestId=' + requestId + ' timing=pre-execution',
      decision_id: requestId,
      shield: 'green',
      tool_params: typeof params === 'object' ? JSON.stringify(params).substring(0, 500) : '',
      prev_hash: prevHash
    };
    var entryStr = JSON.stringify(entry);
    entry.hash = crypto.createHash('sha256').update(entryStr + prevHash).digest('hex');
    
    // Ensure directory exists
    var logDir = path.dirname(AUDIT_LOG_PATH);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + '\n');
    console.log('[GreenShield] Audit: ' + decision + ' tool=' + toolName + ' id=' + requestId);
  } catch (err) {
    console.error('[GreenShield] Audit write failed:', err.message);
  }
}

// ── Consent Card Rendering ─────────────────────────────────────
function showGreenShieldCard(requestId, toolName, toolParams) {
  if (!mainWindow || mainWindow.isDestroyed() || !mainWindow.webContents) {
    console.log('[GreenShield] Window not available — blocking tool (fail-closed)');
    return;
  }

  // Build a human-readable description of what the tool wants to do
  var description = toolName || 'unknown action';
  var detail = '';
  if (toolParams && typeof toolParams === 'object') {
    if (toolParams.command) detail = toolParams.command;
    else if (toolParams.path || toolParams.filePath) detail = toolParams.path || toolParams.filePath;
    else if (toolParams.query) detail = toolParams.query;
    else if (toolParams.url) detail = toolParams.url;
    else if (toolParams.content) detail = (toolParams.content + '').substring(0, 80);
    else {
      var keys = Object.keys(toolParams).slice(0, 3);
      detail = keys.map(function(k) { return k + ': ' + (toolParams[k] + '').substring(0, 40); }).join(', ');
    }
  }
  // Escape for JS string injection
  var safeDetail = (detail + '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '');
  var safeToolName = (toolName + '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");

  var cardJS = `
    (function() {
      var requestId = '${requestId}';
      var old = document.getElementById('crocbox-consent-overlay');
      if (old) old.remove();
      if (!document.getElementById('crocbox-green-consent-style')) {
        var s = document.createElement('style');
        s.id = 'crocbox-green-consent-style';
        s.textContent = '#crocbox-consent-overlay { position:fixed; top:0; right:0; bottom:0; width:360px; z-index:999999; background:rgba(0,0,0,0.92); border-left:3px solid #2E7D32; font-family:-apple-system,BlinkMacSystemFont,sans-serif; color:#f0f0f0; display:flex; flex-direction:column; } #crocbox-consent-overlay button { flex:1; padding:14px 16px; border:none; border-radius:8px; font-size:15px; font-weight:500; cursor:pointer; } #crocbox-btn-allow { background:#2E7D32; color:#fff; } #crocbox-btn-deny { background:#333; color:#f0f0f0; border:1px solid #555; }';
        document.head.appendChild(s);
      }
      var overlay = document.createElement('div');
      overlay.id = 'crocbox-consent-overlay';
      overlay.innerHTML = '<div style="padding:24px 24px 16px; border-bottom:1px solid rgba(46,125,50,0.3)"><div style="text-align:center; margin-bottom:8px"><svg width="48" height="58" viewBox="0 0 100 120" style="display:inline-block"><path d="M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z" fill="#1B5E20" stroke="#2E7D32" stroke-width="3"/><path d="M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z" fill="#2E7D32"/><path d="M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z" fill="#4CAF50"/></svg></div><div style="font-size:17px; font-weight:500; color:#4CAF50; margin-bottom:6px">Green Shield</div><div style="font-size:13px; color:#999">Action Requested</div></div><div style="flex:1; padding:20px 24px"><div style="font-size:14px; color:#ccc; line-height:1.6; margin-bottom:12px">Your AI wants to perform an action. It has <strong>NOT executed yet</strong>. You decide.</div><div style="background:rgba(46,125,50,0.15); border:1px solid rgba(46,125,50,0.3); border-radius:8px; padding:12px; margin-bottom:12px"><div style="font-size:11px; color:#81C784; text-transform:uppercase; margin-bottom:4px">Tool</div><div style="font-size:14px; color:#fff; font-weight:500">${safeToolName}</div></div>' + ('${safeDetail}' ? '<div style="background:rgba(255,255,255,0.05); border-radius:8px; padding:12px"><div style="font-size:11px; color:#999; text-transform:uppercase; margin-bottom:4px">Detail</div><div style="font-size:13px; color:#ccc; word-break:break-all">${safeDetail}</div></div>' : '') + '</div><div style="padding:16px 24px 24px; display:flex; gap:12px"><button id="crocbox-btn-allow">Allow</button><button id="crocbox-btn-deny">Block</button></div>';
      document.body.appendChild(overlay);
      console.log('[CROCbox] Green Shield consent card shown for: ${safeToolName}');
      document.getElementById('crocbox-btn-allow').addEventListener('click', function() {
        console.log('[CROCbox] Green Shield: User clicked ALLOW');
        overlay.remove();
        fetch('http://127.0.0.1:${GREEN_SHIELD_PORT}/green-shield-resolve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: requestId, decision: 'allow' })
        }).catch(function(e) { console.error('[CROCbox] Green Shield resolve failed:', e); });
      });
      document.getElementById('crocbox-btn-deny').addEventListener('click', function() {
        console.log('[CROCbox] Green Shield: User clicked BLOCK');
        overlay.remove();
        fetch('http://127.0.0.1:${GREEN_SHIELD_PORT}/green-shield-resolve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: requestId, decision: 'deny' })
        }).catch(function(e) { console.error('[CROCbox] Green Shield resolve failed:', e); });
      });
    })();
  `;
  mainWindow.webContents.executeJavaScript(cardJS).then(function() {
    console.log('[GreenShield] Consent card rendered for ' + toolName);
  }).catch(function(err) {
    console.error('[GreenShield] Card render failed:', err.message);
  });
}

// ── HTTP Consent Server ────────────────────────────────────────
let server = null;

function startGreenShieldServer(win) {
  mainWindow = win;
  
  server = http.createServer(function(req, res) {
    // CORS headers for local requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
    
    // ── Consent Request (from before_tool_call hook) ──────────
    if (req.method === 'POST' && req.url === '/green-shield-consent') {
      let body = '';
      req.on('data', function(chunk) { body += chunk; });
      req.on('end', function() {
        try {
          var data = JSON.parse(body);
          var toolName = data.toolName || 'unknown';
          var toolParams = data.params || {};
          var requestId = data.requestId || crypto.randomUUID();
          
          console.log('[GreenShield] Consent request: tool=' + toolName + ' id=' + requestId);
          
          // Create a promise that resolves when the NHB decides
          var consentPromise = new Promise(function(resolve) {
            var timer = setTimeout(function() {
              if (pendingGreenConsents.has(requestId)) {
                pendingGreenConsents.delete(requestId);
                writeGreenShieldAudit(requestId, toolName, 'timeout', toolParams);
                resolve({ allowed: false, reason: 'consent-timeout' });
              }
            }, CONSENT_TIMEOUT_MS);
            
            pendingGreenConsents.set(requestId, {
              resolve: resolve,
              timer: timer,
              toolName: toolName,
              params: toolParams
            });
          });
          
          // Show the Green Shield consent card
          showGreenShieldCard(requestId, toolName, toolParams);
          
          // Block the HTTP response until the NHB decides
          consentPromise.then(function(result) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          });
          
        } catch (err) {
          console.error('[GreenShield] Bad consent request:', err.message);
          // Fail-closed: block the tool
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ allowed: false, reason: 'invalid-request' }));
        }
      });
      return;
    }
    
    // ── Consent Resolution (from renderer button click) ───────
    if (req.method === 'POST' && req.url === '/green-shield-resolve') {
      let body = '';
      req.on('data', function(chunk) { body += chunk; });
      req.on('end', function() {
        try {
          var data = JSON.parse(body);
          var requestId = data.requestId;
          var decision = data.decision;
          
          if (!requestId || (decision !== 'allow' && decision !== 'deny')) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid decision' }));
            return;
          }
          
          var pending = pendingGreenConsents.get(requestId);
          if (!pending) {
            console.log('[GreenShield] Resolve: requestId ' + requestId + ' not found (expired or already resolved)');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, note: 'already-resolved' }));
            return;
          }
          
          clearTimeout(pending.timer);
          pendingGreenConsents.delete(requestId);
          
          var allowed = decision === 'allow';
          writeGreenShieldAudit(requestId, pending.toolName, decision, pending.params);
          
          console.log('[GreenShield] Resolved: ' + decision + ' tool=' + pending.toolName + ' id=' + requestId);
          pending.resolve({ allowed: allowed, reason: 'user-' + decision });
          
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, decision: decision }));
          
        } catch (err) {
          console.error('[GreenShield] Bad resolve request:', err.message);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }
    
    // ── Health check ──────────────────────────────────────────
    if (req.method === 'GET' && req.url === '/green-shield-health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, shield: 'green', pending: pendingGreenConsents.size }));
      return;
    }
    
    res.writeHead(404);
    res.end('Not found');
  });
  
  server.listen(GREEN_SHIELD_PORT, '127.0.0.1', function() {
    console.log('[GreenShield] Consent server listening on http://127.0.0.1:' + GREEN_SHIELD_PORT);
    console.log('[GreenShield] Green Shield ACTIVE — Consent Before Execution for ALL tools');
  });
  
  server.on('error', function(err) {
    console.error('[GreenShield] Server error:', err.message);
    if (err.code === 'EADDRINUSE') {
      console.error('[GreenShield] Port ' + GREEN_SHIELD_PORT + ' in use — Green Shield DISABLED, falling back to Yellow Shield');
    }
  });
}

function stopGreenShieldServer() {
  if (server) {
    // Resolve all pending consents as denied (fail-closed)
    for (var [requestId, pending] of pendingGreenConsents) {
      clearTimeout(pending.timer);
      pending.resolve({ allowed: false, reason: 'server-shutdown' });
      writeGreenShieldAudit(requestId, pending.toolName, 'deny', pending.params);
    }
    pendingGreenConsents.clear();
    server.close();
    server = null;
    console.log('[GreenShield] Consent server stopped');
  }
}

module.exports = {
  startGreenShieldServer,
  stopGreenShieldServer,
  GREEN_SHIELD_PORT,
  pendingGreenConsents
};
