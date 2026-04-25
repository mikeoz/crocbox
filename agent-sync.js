/**
 * agent-sync.js — Agent Sync Bridge for CROCbox
 *
 * Observer-only module that forwards consent decisions from the local
 * audit log to the opn.li Supabase project. Runs AFTER the local audit
 * write. Never blocks the consent gate. If Supabase is unreachable,
 * decisions queue locally and drain on next successful connection.
 *
 * Contract (from OPN_2026_FN_Phase-VIII_Wiring-CROCbox-Into_opnli_19APR26.md):
 *   1. POST consent decisions to consent_decisions
 *   2. UPSERT BigCROC state to agent_cards on launch + every 5 min
 *   3. INSERT product_connections row on first sync
 *
 * Wrapper-pattern guarantee: if this file is deleted, CROCbox works
 * exactly as it does today. No modifications to OpenClaw, the gateway,
 * or the Green Shield gate logic.
 */

'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');

// ── Configuration ─────────────────────────────────────────────────
const SUPABASE_URL = 'https://qmpmxrtcysrngfjotkcq.supabase.co';
const ACCOUNT_JSON_PATH = path.join(os.homedir(), '.crocbox', 'account.json');
const QUEUE_PATH = path.join(os.homedir(), 'opnli', 'crocbox', 'logs', 'agent-sync-queue.jsonl');
const QUEUE_CAP = 1000;
const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const REQUEST_TIMEOUT_MS = 10000;

// ── State ─────────────────────────────────────────────────────────
let enabled = false;
let account = null; // { access_token, refresh_token, member_id, email, anon_key, product_registered, ... }
let heartbeatTimer = null;
let sessionCounters = { allowed: 0, blocked: 0, timeout: 0 };
let agentMeta = { agent_name: 'BigCROC', model: 'unknown', shield_level: 'green', skill_count: 0 };

// ── Dry-run harness (for Mini-side verification without credentials) ──
const DRY_RUN = process.env.CROCBOX_AGENT_SYNC_DRY_RUN === '1';

function log(msg) { console.log('[AgentSync] ' + msg); }
function warn(msg) { console.warn('[AgentSync] ' + msg); }
function err(msg) { console.error('[AgentSync] ' + msg); }

// ── Account credentials ───────────────────────────────────────────
function loadAccount() {
  try {
    const raw = fs.readFileSync(ACCOUNT_JSON_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.access_token || !parsed.member_id) {
      warn('account.json present but missing required fields (access_token, member_id) — sync disabled');
      return null;
    }
    return parsed;
  } catch (e) {
    if (e.code === 'ENOENT') {
      log('account.json absent — Local Mode, sync disabled');
    } else {
      warn('account.json unreadable (' + e.message + ') — sync disabled');
    }
    return null;
  }
}

function saveAccount(updated) {
  try {
    fs.writeFileSync(ACCOUNT_JSON_PATH, JSON.stringify(updated, null, 2));
    account = updated;
  } catch (e) {
    warn('account.json write failed: ' + e.message);
  }
}

// ── HTTP helper ───────────────────────────────────────────────────
function httpsRequest(method, urlStr, headers, body) {
  return new Promise(function(resolve, reject) {
    const u = new URL(urlStr);
    const opts = {
      method: method,
      hostname: u.hostname,
      path: u.pathname + u.search,
      headers: headers || {},
      timeout: REQUEST_TIMEOUT_MS
    };
    const req = https.request(opts, function(res) {
      let data = '';
      res.on('data', function(chunk) { data += chunk; });
      res.on('end', function() {
        resolve({ status: res.statusCode, body: data });
      });
    });
    req.on('error', reject);
    req.on('timeout', function() { req.destroy(new Error('request timeout')); });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ── Supabase REST helpers ─────────────────────────────────────────
function supabaseHeaders() {
  return {
    'Content-Type': 'application/json',
    'apikey': account.anon_key || '',
    'Authorization': 'Bearer ' + account.access_token,
    'Prefer': 'return=minimal'
  };
}

async function refreshToken() {
  if (!account || !account.refresh_token) return false;
  try {
    const res = await httpsRequest('POST',
      SUPABASE_URL + '/auth/v1/token?grant_type=refresh_token',
      { 'Content-Type': 'application/json', 'apikey': account.anon_key || '' },
      { refresh_token: account.refresh_token });
    if (res.status === 200) {
      const parsed = JSON.parse(res.body);
      const updated = Object.assign({}, account, {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token || account.refresh_token
      });
      saveAccount(updated);
      log('token refreshed');
      return true;
    }
  } catch (e) {
    warn('token refresh failed: ' + e.message);
  }
  return false;
}

// ── Schema mapping: local audit entry → consent_decisions row ─────
function mapAuditToConsentDecision(entry) {
  const decisionMap = { allowed: 'allowed', blocked: 'revoked' };
  return {
    member_id: account.member_id,
    source_product: 'crocbox',
    entity_name: entry.target || 'unknown-tool',
    entity_type: 'ai_agent_tool',
    decision: decisionMap[entry.result] || 'revoked',
    card_context: {
      entity: agentMeta.agent_name,
      data: entry.tool_params || '',
      use: entry.target || '',
      boundary: 'per-action consent; ' + (entry.reason || 'unknown')
    },
    decision_at: entry.timestamp,
    audit_hash: entry.hash,
    prev_hash: entry.prev_hash || null,
    event_type: 'consent',
    summary_text: buildSummaryText(entry),
    source_reference: entry.decision_id || null
  };
}

function buildSummaryText(entry) {
  const verb = entry.result === 'allowed' ? 'allowed' : 'blocked';
  const phrases = {
    'web_search':       'search the web',
    'web_fetch':        'fetch a web page',
    'bash':             'run a shell command',
    'shell_exec':       'run a shell command',
    'filesystem_read':  'read a file',
    'filesystem-read':  'read a file',
    'filesystem_write': 'write a file',
    'filesystem-write': 'write a file',
    'api_call':         'make an API call'
  };
  const tool = entry.target || '';
  const plain = phrases[tool];
  const action = plain ? plain : (tool ? ('use ' + tool) : 'perform an action');
  return 'You ' + verb + ' ' + agentMeta.agent_name + ' to ' + action;
}

// ── Queue (offline resilience) ────────────────────────────────────
function enqueue(row) {
  try {
    if (!fs.existsSync(path.dirname(QUEUE_PATH))) {
      fs.mkdirSync(path.dirname(QUEUE_PATH), { recursive: true });
    }
    const lineCount = fs.existsSync(QUEUE_PATH)
      ? fs.readFileSync(QUEUE_PATH, 'utf8').split('\n').filter(Boolean).length
      : 0;
    if (lineCount >= QUEUE_CAP) {
      warn('queue at cap (' + QUEUE_CAP + ') — dropping oldest is not implemented; new entry dropped');
      return;
    }
    fs.appendFileSync(QUEUE_PATH, JSON.stringify(row) + '\n');
  } catch (e) {
    warn('enqueue failed: ' + e.message);
  }
}

async function drainQueue() {
  if (!fs.existsSync(QUEUE_PATH)) return;
  let lines;
  try {
    lines = fs.readFileSync(QUEUE_PATH, 'utf8').split('\n').filter(Boolean);
  } catch (e) { return; }
  if (lines.length === 0) return;
  log('draining queue: ' + lines.length + ' entries');
  const successful = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      const row = JSON.parse(lines[i]);
      const ok = await postConsentDecision(row, /*fromQueue*/ true);
      if (ok) successful.push(i); else break; // stop on first failure; preserve order
    } catch (e) { successful.push(i); /* malformed line: skip forever */ }
  }
  // Rewrite queue minus the successful entries
  const remaining = lines.filter(function(_, i) { return successful.indexOf(i) < 0; });
  fs.writeFileSync(QUEUE_PATH, remaining.length ? remaining.join('\n') + '\n' : '');
  if (successful.length > 0) log('drained ' + successful.length + ' queued entries');
}

// ── Responsibility 1: push consent decision ───────────────────────
async function postConsentDecision(row, fromQueue) {
  if (DRY_RUN) {
    console.log('[AgentSync DRY-RUN] POST /rest/v1/consent_decisions');
    console.log(JSON.stringify(row, null, 2));
    return true;
  }
  try {
    const res = await httpsRequest('POST',
      SUPABASE_URL + '/rest/v1/consent_decisions',
      supabaseHeaders(), row);
    if (res.status === 201 || res.status === 200 || res.status === 204) {
      return true;
    }
    if (res.status === 401) {
      const refreshed = await refreshToken();
      if (refreshed) {
        const retry = await httpsRequest('POST',
          SUPABASE_URL + '/rest/v1/consent_decisions',
          supabaseHeaders(), row);
        if (retry.status === 201 || retry.status === 200 || retry.status === 204) return true;
      }
    }
    warn('POST consent_decisions returned ' + res.status + ': ' + res.body.substring(0, 200));
    if (!fromQueue) enqueue(row);
    return false;
  } catch (e) {
    warn('POST consent_decisions failed: ' + e.message);
    if (!fromQueue) enqueue(row);
    return false;
  }
}

function push(auditEntry) {
  if (!enabled) return;
  // Forward only green-shield consent decisions. Other audit entries
  // (e.g. keycard-activation / yellow-shield state) are out of scope for
  // consent_decisions and must not be POSTed.
  if (!auditEntry || auditEntry.action !== 'green-shield') return;
  // Update session counters for heartbeat
  if (auditEntry.result === 'allowed') sessionCounters.allowed++;
  else if (auditEntry.reason === 'user-timeout') sessionCounters.timeout++;
  else sessionCounters.blocked++;
  // Fire-and-forget; do not await. We must never block the gate.
  const row = mapAuditToConsentDecision(auditEntry);
  postConsentDecision(row, false).catch(function(e) {
    warn('push unhandled error: ' + e.message);
  });
}

// ── Responsibility 2: heartbeat (UPSERT agent_cards) ──────────────
async function heartbeat() {
  if (!enabled) return;
  const row = {
    member_id: account.member_id,
    agent_id: 'bigcroc',
    agent_name: agentMeta.agent_name,
    model: agentMeta.model,
    shield_level: agentMeta.shield_level,
    skill_count: agentMeta.skill_count,
    allowed_count: sessionCounters.allowed,
    blocked_count: sessionCounters.blocked,
    timeout_count: sessionCounters.timeout,
    last_seen_at: new Date().toISOString()
  };
  if (DRY_RUN) {
    console.log('[AgentSync DRY-RUN] UPSERT /rest/v1/agent_cards');
    console.log(JSON.stringify(row, null, 2));
    return;
  }
  try {
    const headers = Object.assign({}, supabaseHeaders(), { 'Prefer': 'resolution=merge-duplicates,return=minimal' });
    const res = await httpsRequest('POST',
      SUPABASE_URL + '/rest/v1/agent_cards?on_conflict=member_id,agent_id',
      headers, row);
    if (res.status !== 201 && res.status !== 200 && res.status !== 204) {
      warn('heartbeat UPSERT agent_cards returned ' + res.status);
    }
  } catch (e) {
    warn('heartbeat failed: ' + e.message);
  }
  // Drain any queued decisions opportunistically after a successful heartbeat connection
  drainQueue().catch(function(e) { warn('drainQueue error: ' + e.message); });
}

// ── Responsibility 3: register product connection on first sync ──
async function registerProductConnection() {
  if (!enabled) return;
  if (account.product_registered === true) return;
  const row = {
    member_id: account.member_id,
    product_type: 'crocbox',
    instance_id: os.hostname(),
    platform: 'macOS ' + os.release(),
    version: getCrocboxVersion(),
    sync_status: 'healthy',
    last_sync_at: new Date().toISOString()
  };
  if (DRY_RUN) {
    console.log('[AgentSync DRY-RUN] INSERT /rest/v1/product_connections');
    console.log(JSON.stringify(row, null, 2));
    saveAccount(Object.assign({}, account, { product_registered: true }));
    return;
  }
  try {
    const res = await httpsRequest('POST',
      SUPABASE_URL + '/rest/v1/product_connections',
      supabaseHeaders(), row);
    if (res.status === 201 || res.status === 200 || res.status === 204) {
      saveAccount(Object.assign({}, account, { product_registered: true }));
      log('product_connections row registered');
    } else {
      warn('registerProductConnection returned ' + res.status + ': ' + res.body.substring(0, 200));
    }
  } catch (e) {
    warn('registerProductConnection failed: ' + e.message);
  }
}

function getCrocboxVersion() {
  try {
    return require('./package.json').version;
  } catch (e) { return 'unknown'; }
}

// ── Public API ────────────────────────────────────────────────────
function init(options) {
  options = options || {};
  if (options.agent_name) agentMeta.agent_name = options.agent_name;
  if (options.model) agentMeta.model = options.model;
  if (options.shield_level) agentMeta.shield_level = options.shield_level;
  if (typeof options.skill_count === 'number') agentMeta.skill_count = options.skill_count;

  account = loadAccount();
  if (!account) {
    enabled = false;
    return;
  }
  enabled = true;
  log('enabled — member_id=' + String(account.member_id).substring(0, 8) + '...');
  // Fire-and-forget registration + first heartbeat + queue drain
  registerProductConnection().catch(function(e) { warn('init register error: ' + e.message); });
  heartbeat().catch(function(e) { warn('init heartbeat error: ' + e.message); });
  if (heartbeatTimer) clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(function() {
    heartbeat().catch(function(e) { warn('interval heartbeat error: ' + e.message); });
  }, HEARTBEAT_INTERVAL_MS);
  if (heartbeatTimer && heartbeatTimer.unref) heartbeatTimer.unref();
}

function isEnabled() { return enabled; }

function shutdown() {
  if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
  enabled = false;
}

module.exports = {
  init: init,
  push: push,
  heartbeat: heartbeat,
  isEnabled: isEnabled,
  shutdown: shutdown,
  // exported for dry-run harness + tests
  _mapAuditToConsentDecision: mapAuditToConsentDecision
};
