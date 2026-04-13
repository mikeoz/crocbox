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

// Callback to notify main.js of consent requests (set via setConsentCallback)
let consentCallback = null;
let timeoutCallback = null;

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

// ── Consent Notification (via IPC callback to main.js) ────
function notifyConsentRequest(requestId, toolName, toolParams) {
  if (typeof consentCallback === 'function') {
    consentCallback({ requestId: requestId, toolName: toolName, toolParams: toolParams });
  } else {
    console.log('[GreenShield] No consent callback registered — blocking tool (fail-closed)');
  }
}

// ── HTTP Consent Server ────────────────────────────────────────
let server = null;

function startGreenShieldServer() {
  
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
                if (typeof timeoutCallback === 'function') {
                  timeoutCallback({ requestId: requestId, toolName: toolName });
                }
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
          notifyConsentRequest(requestId, toolName, toolParams);
          
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
    
    // ── Consent Resolution now handled via IPC (main.js calls resolveGreenConsent) ──

    // ── Health check // ── Health check ──────────────────────────────────────────
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

// Called by main.js when renderer sends a consent decision via IPC
function resolveGreenConsent(requestId, decision) {
  if (!requestId || (decision !== 'allow' && decision !== 'deny')) {
    console.log('[GreenShield] resolveGreenConsent: invalid args — requestId=' + requestId + ' decision=' + decision);
    return { ok: false, error: 'invalid-args' };
  }
  var pending = pendingGreenConsents.get(requestId);
  if (!pending) {
    console.log('[GreenShield] resolveGreenConsent: requestId ' + requestId + ' not found (expired or already resolved)');
    return { ok: true, note: 'already-resolved' };
  }
  clearTimeout(pending.timer);
  pendingGreenConsents.delete(requestId);
  var allowed = decision === 'allow';
  writeGreenShieldAudit(requestId, pending.toolName, decision, pending.params);
  console.log('[GreenShield] Resolved via IPC: ' + decision + ' tool=' + pending.toolName + ' id=' + requestId);
  pending.resolve({ allowed: allowed, reason: 'user-' + decision });
  return { ok: true, decision: decision };
}

function setConsentCallback(cb) {
  consentCallback = cb;
  console.log('[GreenShield] Consent callback registered');
}

function setTimeoutCallback(cb) {
  timeoutCallback = cb;
  console.log('[GreenShield] Timeout callback registered');
}

module.exports = {
  startGreenShieldServer,
  stopGreenShieldServer,
  resolveGreenConsent,
  setConsentCallback,
  setTimeoutCallback,
  GREEN_SHIELD_PORT,
  pendingGreenConsents
};
