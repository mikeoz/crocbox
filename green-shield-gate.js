/**
 * green-shield-gate.js — Green Shield Consent Gate for CROCbox
 * OTN-Connected (v2) — August 15, 2026
 * 
 * This module provides a local HTTP consent server that the modified
 * before_tool_call hook in the bundled OpenClaw agent runtime calls
 * before executing ANY tool.
 * 
 * v2 Change: The gate now submits holds to consent.opn.li/v1/submit
 * AND shows the local consent card. When the NHB decides locally,
 * the gate calls /v1/decide to resolve the remote hold (writes to
 * the hash chain) AND returns the decision to OpenClaw.
 * 
 * Architecture:
 *   Agent runtime (before_tool_call hook)
 *     -> HTTP POST http://127.0.0.1:{port}/green-shield-consent
 *       -> Gate POSTs to consent.opn.li/v1/submit (blocks remotely)
 *       -> SIMULTANEOUSLY: main.js renders Green Shield consent card
 *         -> NHB clicks Allow or Block
 *           -> Gate calls consent.opn.li/v1/decide/:id/:action
 *           -> /v1/submit unblocks, returns { allowed: true/false }
 *             -> Gate returns decision to OpenClaw
 * 
 * Fail-closed: If the consent server is unreachable, the tool is blocked.
 * If the NHB doesn't respond within the timeout, the tool is blocked.
 * There is no bypass.
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ── Configuration ──────────────────────────────────────────────
const GREEN_SHIELD_PORT = 18793;
const CONSENT_TIMEOUT_MS = 60000;

// OTN Consent Server config (from .env)
let CONSENT_SERVER_URL = process.env.CONSENT_SERVER_URL || '';
let CONSENT_SUBMIT_SECRET = process.env.CONSENT_SUBMIT_SECRET || '';
let CROCBOX_MEMBER_ID = process.env.CROCBOX_MEMBER_ID || '';
let OTN_CONNECTED = !!(CONSENT_SERVER_URL && CONSENT_SUBMIT_SECRET && CROCBOX_MEMBER_ID);

// ── State ──────────────────────────────────────────────────────
const pendingGreenConsents = new Map();
let consentCallback = null;
let timeoutCallback = null;
// RE-1: the chain receipt callback, and how long we wait for the chain answer
// before telling the NHB the decision was not recorded.
let receiptCallback = null;
var RECEIPT_WAIT_MS = 15000;
// Step 5: a standing rule answers at /v1/submit and returns immediately; a hold
// that needs a human blocks there. This is how long the gate waits for a rule
// answer before deciding the NHB must be asked. Fail-closed: on expiry, ask.
let ruleAppliedCallback = null;
var RULE_FAST_PATH_MS = 900;

// ── Local Audit Logger (backup) ────────────────────────────────
const AUDIT_LOG_PATH = path.join(
  process.env.HOME || '/tmp', 'opnli', 'crocbox', 'logs', 'crocbox-audit.jsonl'
);

function writeLocalAudit(requestId, toolName, decision, params) {
  try {
    var prevHash = 'genesis';
    try {
      var lines = fs.readFileSync(AUDIT_LOG_PATH, 'utf8').trim().split('\n');
      if (lines.length > 0) {
        var lastEntry = JSON.parse(lines[lines.length - 1]);
        prevHash = lastEntry.hash || 'genesis';
      }
    } catch (e) { /* file may not exist yet */ }

    var entry = {
      timestamp: new Date().toISOString(),
      action: 'green-shield',
      target: toolName || 'unknown-tool',
      result: decision === 'allow' ? 'allowed' : 'blocked',
      reason: decision === 'allow' ? 'user-consent' : (decision === 'timeout' ? 'user-timeout' : 'user-deny'),
      detail: 'tool=' + toolName + ' requestId=' + requestId + ' timing=pre-execution',
      decision_id: requestId,
      shield: 'green',
      tool_params: typeof params === 'object' ? JSON.stringify(params).substring(0, 500) : '',
      prev_hash: prevHash
    };
    var entryStr = JSON.stringify(entry);
    entry.hash = crypto.createHash('sha256').update(entryStr + prevHash).digest('hex');
    var logDir = path.dirname(AUDIT_LOG_PATH);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(entry) + '\n');
    console.log('[GreenShield] Local audit: ' + decision + ' tool=' + toolName + ' id=' + requestId);
  } catch (err) {
    console.error('[GreenShield] Local audit write failed:', err.message);
  }
}

// ── OTN Consent Server Integration ────────────────────────────
function submitToOTN(toolName, params, sessionId) {
  return new Promise(function(resolve) {
    if (!OTN_CONNECTED) {
      console.log('[GreenShield] OTN not configured — local-only mode');
      resolve({ otnHoldId: null });
      return;
    }

    var detail = '';
    if (params) {
      if (params.command) detail = params.command;
      else if (params.path || params.filePath) detail = params.path || params.filePath;
      else if (params.query) detail = params.query;
      else if (params.url) detail = params.url;
      else if (params.content) detail = (params.content + '').substring(0, 80);
    }

    var holdPayload = JSON.stringify({
      action_type: toolName,
      target: detail || toolName,
      member_id: CROCBOX_MEMBER_ID,
      source_product: 'crocbox',
      source_entity_id: '98e6797e-9ebd-424a-9f5c-5923bad048fe',
      entity_name: 'CROCbox',
      entity_type: 'ai_agent',
      session_id: sessionId,
      summary_text: toolName + ': ' + (detail || '(no detail)')
    });

    var url = new URL(CONSENT_SERVER_URL + '/v1/submit');
    var options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET,
        'Content-Length': Buffer.byteLength(holdPayload)
      },
      timeout: 70000
    };

    console.log('[GreenShield] OTN: submitting hold for ' + toolName);

    var req = https.request(options, function(res) {
      var body = '';
      res.on('data', function(chunk) { body += chunk; });
      res.on('end', function() {
        try {
          var result = JSON.parse(body);
          console.log('[GreenShield] OTN: submit returned — allowed=' + result.allowed);
          resolve({ otnResult: result });
        } catch (e) {
          console.error('[GreenShield] OTN: bad response — ' + body.substring(0, 200));
          resolve({ otnResult: { allowed: false, reason: 'bad-response' } });
        }
      });
    });

    req.on('error', function(err) {
      console.error('[GreenShield] OTN: submit failed — ' + err.message);
      resolve({ otnResult: { allowed: false, reason: 'consent-server-unreachable' } });
    });

    req.on('timeout', function() {
      req.destroy();
      console.error('[GreenShield] OTN: submit timed out');
      resolve({ otnResult: { allowed: false, reason: 'consent-server-timeout' } });
    });

    req.write(holdPayload);
    req.end();
  });
}

function decideOnOTN(holdId, decision) {
  if (!OTN_CONNECTED || !holdId) return;

  var action = decision === 'allow' ? 'allow' : 'deny';
  var url = new URL(CONSENT_SERVER_URL + '/v1/decide/' + holdId + '/' + action);

  var req = https.request({
    hostname: url.hostname,
    port: url.port || 443,
    path: url.pathname,
    method: "POST",
    headers: { 'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET },
    timeout: 10000
  }, function(res) {
    var body = '';
    res.on('data', function(chunk) { body += chunk; });
    res.on('end', function() {
      console.log('[GreenShield] OTN: decide ' + action + ' for hold ' + holdId + ' — ' + res.statusCode);
    });
  });

  req.on('error', function(err) {
    console.error('[GreenShield] OTN: decide failed — ' + err.message);
  });

  req.end();
}

// ── Consent Notification ───────────────────────────────────────
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
  if (OTN_CONNECTED) {
    console.log('[GreenShield] OTN mode: consent.opn.li connected');
    console.log('[GreenShield] member_id: ' + CROCBOX_MEMBER_ID);
    console.log('[GreenShield] source_product: crocbox');
  } else {
    console.log('[GreenShield] Local-only mode (OTN credentials not configured)');
  }

  server = http.createServer(function(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    if (req.method === 'POST' && req.url === '/green-shield-consent') {
      let body = '';
      req.on('data', function(chunk) { body += chunk; });
      req.on('end', function() {
        try {
          var data = JSON.parse(body);
          var toolName = data.toolName || 'unknown';
          var toolParams = data.params || {};
          var requestId = data.requestId || crypto.randomUUID();
          var sessionId = 'crocbox-' + Date.now().toString(36);

          console.log('[GreenShield] Consent request: tool=' + toolName + ' id=' + requestId);

          // Submit to OTN consent server (non-blocking from gate's perspective)
          // The OTN submit will block on ITS end until decided via /v1/decide
          var otnPromise = submitToOTN(toolName, toolParams, sessionId);

          // Shows the local consent card and waits for the NHB. Called only when
          // no standing rule has already answered this question.
          function startLocalPrompt() {
            var localPromise = new Promise(function(resolve) {
              var timer = setTimeout(function() {
                if (pendingGreenConsents.has(requestId)) {
                  pendingGreenConsents.delete(requestId);
                  writeLocalAudit(requestId, toolName, 'timeout', toolParams);
                  if (typeof timeoutCallback === 'function') {
                    timeoutCallback({ requestId: requestId, toolName: toolName });
                  }
                  resolve({ allowed: false, reason: 'consent-timeout', decision: 'timeout' });
                }
              }, CONSENT_TIMEOUT_MS);

              pendingGreenConsents.set(requestId, {
                resolve: resolve,
                timer: timer,
                toolName: toolName,
                params: toolParams,
                otnPromise: otnPromise
              });
            });

            notifyConsentRequest(requestId, toolName, toolParams);

            // The local decision drives the response to OpenClaw
            localPromise.then(function(result) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ allowed: result.allowed, reason: result.reason }));
            });
          }

          // Step 5 fast path. A standing rule is decided inside /v1/submit and
          // returns at once; a hold needing a human blocks there for up to 70s.
          // If the answer arrives inside RULE_FAST_PATH_MS carrying reason
          // 'rule', the NHB has already answered this and must not be asked
          // again. Every other outcome falls through to the card.
          // Records the rule decision and puts the receipt on screen. Used by
          // both paths below. Does not write the HTTP response — the caller does,
          // because who answers OpenClaw differs between the two paths.
          function finishByRule(rr, wasLate) {
            var ruleDecision = rr.allowed ? 'allow' : 'deny';
            console.log('[GreenShield] Rule decided ' + ruleDecision + ' for ' + toolName +
                        (wasLate ? ' — question withdrawn, NHB had not answered'
                                 : ' — NHB not interrupted') +
                        ' (rule ' + (rr.rule_id || 'unknown') + ')');
            writeLocalAudit(requestId, toolName, ruleDecision, toolParams);

            if (typeof ruleAppliedCallback === 'function') {
              try {
                ruleAppliedCallback({
                  requestId: requestId,
                  toolName: toolName,
                  toolParams: toolParams,
                  decision: ruleDecision,
                  rule_id: rr.rule_id || null,
                  rule_sentence: rr.rule_sentence || null,
                  audit_hash: rr.audit_hash || null,
                  recorded: !!rr.audit_hash
                });
              } catch (e) {
                console.error('[GreenShield] Rule-applied callback threw — ' + e.message);
              }
            } else {
              console.error('[GreenShield] No rule-applied callback — receipt not shown');
            }
          }

          var fastPathSettled = false;
          var fastTimer = setTimeout(function() {
            if (fastPathSettled) return;
            fastPathSettled = true;
            startLocalPrompt();
          }, RULE_FAST_PATH_MS);

          otnPromise.then(function(r) {
            var rr = (r && r.otnResult) || null;
            var byRule = !!(rr && rr.reason === 'rule');

            // FAST PATH — the answer beat the card. No card is ever shown.
            if (!fastPathSettled) {
              fastPathSettled = true;
              clearTimeout(fastTimer);
              if (!byRule) {
                startLocalPrompt();
                return;
              }
              finishByRule(rr, false);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ allowed: !!rr.allowed, reason: 'rule' }));
              return;
            }

            // LATE PATH — the card is already up. The Consent Server must
            // evaluate the rule and write two chain rows before it answers, so
            // this is the common case, not the exception.
            if (!byRule) return;

            var pend = pendingGreenConsents.get(requestId);
            if (!pend) {
              // The NHB already answered, or it timed out. Their answer stands.
              return;
            }

            // Withdraw the question. The NHB should never have to answer
            // something their own rule already answered.
            clearTimeout(pend.timer);
            pendingGreenConsents.delete(requestId);
            finishByRule(rr, true);
            pend.resolve({
              allowed: !!rr.allowed,
              reason: 'rule',
              decision: rr.allowed ? 'allow' : 'deny'
            });
          }).catch(function(err) {
            if (fastPathSettled) return;
            fastPathSettled = true;
            clearTimeout(fastTimer);
            console.error('[GreenShield] Submit rejected — asking the NHB: ' + err.message);
            startLocalPrompt();
          });

        } catch (err) {
          console.error('[GreenShield] Bad consent request:', err.message);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ allowed: false, reason: 'invalid-request' }));
        }
      });
      return;
    }

    if (req.method === 'GET' && req.url === '/green-shield-health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        shield: 'green',
        otn: OTN_CONNECTED,
        pending: pendingGreenConsents.size
      }));
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
  });
}

function stopGreenShieldServer() {
  if (server) {
    for (var [requestId, pending] of pendingGreenConsents) {
      clearTimeout(pending.timer);
      pending.resolve({ allowed: false, reason: 'server-shutdown' });
      writeLocalAudit(requestId, pending.toolName, 'deny', pending.params);
    }
    pendingGreenConsents.clear();
    server.close();
    server = null;
    console.log('[GreenShield] Consent server stopped');
  }
}

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

  // Write local audit
  writeLocalAudit(requestId, pending.toolName, decision, pending.params);

  // The OTN submit is still blocking on the consent server.
  // We need to resolve it by calling /v1/decide.
  // But we don't have the OTN hold ID here — the submit call
  // hasn't returned yet. The submit will return once we call decide,
  // but we need the hold ID to call decide.
  //
  // Solution: the /v1/submit call on the consent server creates a
  // hold with an auto-generated ID and blocks. The /v1/pending
  // endpoint lists pending holds. We need to find our hold and
  // decide it.
  //
  // For the interim approach: fire-and-forget a decide call by
  // looking up the pending hold for this member + source_product.
  if (OTN_CONNECTED) {
    findAndDecideOTNHold(decision);
  }

  // RE-1: carry the chain answer back to the screen, or say it was not recorded
  emitReceipt(requestId, pending.otnPromise, decision);

  console.log('[GreenShield] Resolved: ' + decision + ' tool=' + pending.toolName + ' id=' + requestId);
  pending.resolve({ allowed: allowed, reason: 'user-' + decision, decision: decision });
  return { ok: true, decision: decision };
}

function findAndDecideOTNHold(decision) {
  var action = decision === 'allow' ? 'allow' : 'deny';
  var pendingUrl = new URL(CONSENT_SERVER_URL + '/v1/pending');
  pendingUrl.searchParams.set('member_id', CROCBOX_MEMBER_ID);

  var req = https.request({
    hostname: pendingUrl.hostname,
    port: pendingUrl.port || 443,
    path: pendingUrl.pathname + pendingUrl.search,
    method: "GET",
    headers: { 'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET },
    timeout: 10000
  }, function(res) {
    var body = '';
    res.on('data', function(chunk) { body += chunk; });
    res.on('end', function() {
      try {
        var result = JSON.parse(body);
        var holds = result.pending || result;
        if (Array.isArray(holds)) {
          // Find the CROCbox hold (source_product = 'crocbox')
          var crocboxHold = holds.find(function(h) {
            return h.source_product === 'crocbox';
          });
          if (crocboxHold && crocboxHold.id) {
            console.log('[GreenShield] OTN: found hold ' + crocboxHold.id + ' — deciding ' + action);
            decideOnOTN(crocboxHold.id, decision);
          } else {
            console.log('[GreenShield] OTN: no crocbox hold found in pending (' + holds.length + ' total)');
          }
        }
      } catch (e) {
        console.error('[GreenShield] OTN: pending parse error — ' + e.message);
      }
    });
  });

  req.on('error', function(err) {
    console.error('[GreenShield] OTN: pending lookup failed — ' + err.message);
  });

  req.end();
}

function setConsentCallback(cb) {
  consentCallback = cb;
  console.log('[GreenShield] Consent callback registered');
}

function setTimeoutCallback(cb) {
  timeoutCallback = cb;
  console.log('[GreenShield] Timeout callback registered');
}

function setReceiptCallback(cb) {
  receiptCallback = cb;
  console.log('[GreenShield] Receipt callback registered');
}

function setRuleAppliedCallback(cb) {
  ruleAppliedCallback = cb;
  console.log('[GreenShield] Rule-applied callback registered');
}

// RE-1: A decision that is not recorded must not be presented as recorded.
// The /v1/submit answer carries audit_hash. Until now nothing read it.
// We wait for that answer and report it — hash present or hash absent.
// Absent, unreachable, malformed, or slow all report the same thing: NOT RECORDED.
function emitReceipt(requestId, otnPromise, decision) {
  if (typeof receiptCallback !== 'function') {
    console.log('[GreenShield] Receipt: no callback registered — receipt not reported');
    return;
  }

  function send(auditHash, reason) {
    try {
      receiptCallback({
        requestId: requestId,
        decision: decision,
        audit_hash: auditHash || null,
        recorded: !!auditHash,
        reason: reason || null
      });
    } catch (e) {
      console.error('[GreenShield] Receipt: callback threw — ' + e.message);
    }
  }

  if (!OTN_CONNECTED || !otnPromise) {
    console.error('[GreenShield] Receipt: local-only mode — decision is NOT on the chain');
    send(null, 'local-only');
    return;
  }

  var settled = false;
  var timer = setTimeout(function() {
    if (settled) return;
    settled = true;
    console.error('[GreenShield] Receipt: no chain answer within ' + RECEIPT_WAIT_MS + 'ms — reporting NOT RECORDED');
    send(null, 'receipt-timeout');
  }, RECEIPT_WAIT_MS);

  otnPromise.then(function(r) {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    var res = (r && r.otnResult) || {};
    if (res.audit_hash) {
      console.log('[GreenShield] Receipt: chain hash received for ' + requestId);
    } else {
      console.error('[GreenShield] Receipt: submit returned no audit_hash — reporting NOT RECORDED (reason=' + (res.reason || 'none') + ')');
    }
    send(res.audit_hash || null, res.reason || null);
  }).catch(function(err) {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    console.error('[GreenShield] Receipt: submit promise rejected — ' + err.message);
    send(null, 'submit-error');
  });
}


// ── Remote Consent Polling (Item 39) ───────────────────────────
// ai-proxy submits tool consent holds to the Consent Server with
// source_product: "crocbox". This polling loop finds those holds
// and surfaces them through the same consentCallback that the
// local gate uses — so preload.js shows the same five-choice card.

const REMOTE_POLL_MS = 1500;
const pendingRemoteConsents = new Map();
let remotePolling = false;
let remotePollTimer = null;

function startRemoteConsentPolling() {
  if (!OTN_CONNECTED) {
    console.log('[GreenShield] Remote polling: skipped (OTN not configured)');
    return;
  }
  if (remotePolling) return;
  remotePolling = true;
  console.log('[GreenShield] Remote polling: started (every ' + REMOTE_POLL_MS + 'ms)');
  schedulePoll();
}

function stopRemoteConsentPolling() {
  remotePolling = false;
  if (remotePollTimer) {
    clearTimeout(remotePollTimer);
    remotePollTimer = null;
  }
  // Timeout any pending remote consents
  for (var [holdId, entry] of pendingRemoteConsents) {
    clearTimeout(entry.timer);
    writeLocalAudit(holdId, entry.toolName, 'timeout', {});
    if (typeof timeoutCallback === 'function') {
      timeoutCallback({ requestId: holdId, toolName: entry.toolName });
    }
  }
  pendingRemoteConsents.clear();
  console.log('[GreenShield] Remote polling: stopped');
}

function schedulePoll() {
  if (!remotePolling) return;
  remotePollTimer = setTimeout(function() {
    pollRemoteConsent();
  }, REMOTE_POLL_MS);
}

function pollRemoteConsent() {
  if (!remotePolling) return;

  var pendingUrl = new URL(CONSENT_SERVER_URL + '/v1/pending');
  pendingUrl.searchParams.set('member_id', CROCBOX_MEMBER_ID);

  var req = https.request({
    hostname: pendingUrl.hostname,
    port: pendingUrl.port || 443,
    path: pendingUrl.pathname + pendingUrl.search,
    method: 'GET',
    headers: { 'Authorization': 'Bearer ' + CONSENT_SUBMIT_SECRET },
    timeout: 10000
  }, function(res) {
    var body = '';
    res.on('data', function(chunk) { body += chunk; });
    res.on('end', function() {
      try {
        var result = JSON.parse(body);
        var holds = result.pending || result;
        if (Array.isArray(holds)) {
          var crocboxHolds = holds.filter(function(h) {
            return h.source_product === 'crocbox';
          });
          for (var i = 0; i < crocboxHolds.length; i++) {
            var hold = crocboxHolds[i];
            var holdId = hold.id || hold.request_id;
            if (!holdId) continue;
            // Skip if we already surfaced this hold, or if a local consent
            // is already pending (avoid showing two cards at once)
            if (pendingRemoteConsents.has(holdId)) continue;
            if (pendingGreenConsents.size > 0) continue;

            console.log('[GreenShield] Remote hold found: ' + holdId + ' action=' + hold.action_type + ' target=' + (hold.target || ''));

            var toolName = hold.action_type || hold.action || 'unknown';
            var toolParams = { target: hold.target || '', summary: hold.summary_text || '' };

            // Set a timeout for this remote hold
            var timer = setTimeout((function(hid, tn) {
              return function() {
                if (pendingRemoteConsents.has(hid)) {
                  pendingRemoteConsents.delete(hid);
                  writeLocalAudit(hid, tn, 'timeout', {});
                  console.log('[GreenShield] Remote hold timed out: ' + hid);
                  if (typeof timeoutCallback === 'function') {
                    timeoutCallback({ requestId: hid, toolName: tn });
                  }
                }
              };
            })(holdId, toolName), CONSENT_TIMEOUT_MS);

            pendingRemoteConsents.set(holdId, {
              holdId: holdId,
              toolName: toolName,
              params: toolParams,
              hold: hold,
              timer: timer
            });

            // Fire the same callback that local consent uses
            notifyConsentRequest(holdId, toolName, toolParams);
          }
        }
      } catch (e) {
        console.error('[GreenShield] Remote poll parse error: ' + e.message);
      }
      schedulePoll();
    });
  });

  req.on('error', function(err) {
    console.error('[GreenShield] Remote poll error: ' + err.message);
    schedulePoll();
  });

  req.on('timeout', function() {
    req.destroy();
    console.error('[GreenShield] Remote poll timed out');
    schedulePoll();
  });

  req.end();
}

function resolveRemoteConsent(holdId, decision) {
  var entry = pendingRemoteConsents.get(holdId);
  if (!entry) {
    console.log('[GreenShield] resolveRemoteConsent: holdId ' + holdId + ' not found');
    return { ok: false, error: 'not-found' };
  }

  clearTimeout(entry.timer);
  pendingRemoteConsents.delete(holdId);

  writeLocalAudit(holdId, entry.toolName, decision, entry.params);

  // Call /v1/decide on the Consent Server directly
  decideOnOTN(holdId, decision);

  console.log('[GreenShield] Remote resolved: ' + decision + ' tool=' + entry.toolName + ' holdId=' + holdId);

  // Emit receipt — for remote holds, the chain write happens server-side
  // when /v1/decide is called. We report the decision and let the receipt
  // callback handle the "recorded" status via polling or the decide response.
  if (typeof receiptCallback === 'function') {
    try {
      receiptCallback({
        requestId: holdId,
        decision: decision,
        audit_hash: null,
        recorded: false,
        reason: 'remote-decide-sent'
      });
    } catch (e) {
      console.error('[GreenShield] Remote receipt callback threw: ' + e.message);
    }
  }

  return { ok: true, decision: decision };
}


// ── Reinitialize after activation (Item 21) ───────────────────
// Called by main.js after completeActivation sets process.env values.
// Re-reads config from process.env, restarts gate and polling if
// the OTN credentials are now available.
function reinitializeGate() {
  CONSENT_SERVER_URL = process.env.CONSENT_SERVER_URL || '';
  CONSENT_SUBMIT_SECRET = process.env.CONSENT_SUBMIT_SECRET || '';
  CROCBOX_MEMBER_ID = process.env.CROCBOX_MEMBER_ID || '';
  OTN_CONNECTED = !!(CONSENT_SERVER_URL && CONSENT_SUBMIT_SECRET && CROCBOX_MEMBER_ID);
  console.log('[GreenShield] Reinitialize: OTN_CONNECTED=' + OTN_CONNECTED + ' member_id=' + CROCBOX_MEMBER_ID);
  if (OTN_CONNECTED && !remotePolling) {
    startRemoteConsentPolling();
  }
}

module.exports = {
  setReceiptCallback,
  setRuleAppliedCallback,
  startGreenShieldServer,
  stopGreenShieldServer,
  resolveGreenConsent,
  resolveRemoteConsent,
  startRemoteConsentPolling,
  stopRemoteConsentPolling,
  setConsentCallback,
  setTimeoutCallback,
  GREEN_SHIELD_PORT,
  pendingGreenConsents,
  pendingRemoteConsents,
  reinitializeGate
};
