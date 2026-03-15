/**
 * card_ve_client.js — VE Client Module (ENG-VE-01)
 * 
 * Opn.li Agent Trust Layer — Verification Endpoint Client
 * 
 * This module is the internal prototype of card_consent_gate() that will
 * become the public-facing DevKit API. Building it correctly inside CROCbox
 * is how CROCbox becomes the reference implementation.
 * 
 * Three functions:
 *   enroll(opnli_account_id, rental_ski_level) — Register agent with VE
 *   verify(operation_type, card_id, session_id) — Verify a CARD operation
 *   checkStatus(agent_id) — Confirm agent standing on startup
 * 
 * Critical invariants:
 *   - Fail-closed is non-negotiable. Timeout = denied. Network error = denied.
 *   - VE_ENDPOINT configured via environment variable.
 *   - request_hash: SHA-256 of agent_id + card_id + operation_type + session_id + timestamp.
 *   - 3-second timeout on verify(). No exceptions.
 *   - Exponential backoff with jitter on 429 responses.
 * 
 * @version 0.7.0
 * @see OPN_ENG_VE-Requirements_14MAR26_v1.0, Section 9 (ENG-VE-01)
 * @see OPN_ENG_CROC-E2E-Invariants_13MAR26_v2.md
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CROCBOX_VERSION = '0.7.0';
const AGENT_TYPE = 'openclaw';
const VERIFY_TIMEOUT_MS = 3000;       // Fail-closed at 3 seconds. Non-negotiable.
const STATUS_TIMEOUT_MS = 5000;       // checkStatus is startup-only, slightly longer OK.
const ENROLL_TIMEOUT_MS = 10000;      // Enrollment is one-time, user is waiting.
const MAX_BACKOFF_MS = 30000;         // Cap exponential backoff at 30 seconds.
const BASE_BACKOFF_MS = 1000;         // Base for exponential backoff.
const MAX_RETRIES_429 = 3;           // Max retries on 429 before giving up.

// ---------------------------------------------------------------------------
// .env file management
// ---------------------------------------------------------------------------

/**
 * Resolve the .env file path.
 * CROCbox stores its .env at ~/Library/Application Support/CROCbox/.env
 * Per E2E Invariants INV-2, this is created on first launch.
 * For development/testing, override with CROCBOX_ENV_PATH.
 */
function getEnvPath() {
  if (process.env.CROCBOX_ENV_PATH) {
    return process.env.CROCBOX_ENV_PATH;
  }
  const homeDir = process.env.HOME || process.env.USERPROFILE || '/tmp';
  return path.join(homeDir, 'Library', 'Application Support', 'CROCbox', '.env');
}

/**
 * Read a value from the .env file.
 * Returns null if the file doesn't exist or the key isn't found.
 */
function readEnvValue(key) {
  const envPath = getEnvPath();
  try {
    const content = fs.readFileSync(envPath, 'utf8');
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;
      const eqIndex = trimmed.indexOf('=');
      const k = trimmed.substring(0, eqIndex).trim();
      const v = trimmed.substring(eqIndex + 1).trim();
      if (k === key) return v;
    }
  } catch (err) {
    // File doesn't exist or can't be read — expected on first run
  }
  return null;
}

/**
 * Write or update a key=value pair in the .env file.
 * Creates the file if it doesn't exist.
 * Preserves existing content and comments.
 */
function writeEnvValue(key, value) {
  const envPath = getEnvPath();
  const dir = path.dirname(envPath);

  // Ensure directory exists
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  let lines = [];
  let found = false;

  try {
    const content = fs.readFileSync(envPath, 'utf8');
    lines = content.split('\n');
  } catch (err) {
    // File doesn't exist — will create
  }

  // Update existing key or mark as not found
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const eqIndex = trimmed.indexOf('=');
    const k = trimmed.substring(0, eqIndex).trim();
    if (k === key) {
      lines[i] = `${key}=${value}`;
      found = true;
      break;
    }
  }

  // Append if not found
  if (!found) {
    // Add a blank line before if file has content and doesn't end with newline
    if (lines.length > 0 && lines[lines.length - 1].trim() !== '') {
      lines.push('');
    }
    lines.push(`${key}=${value}`);
  }

  fs.writeFileSync(envPath, lines.join('\n'), 'utf8');
}

// ---------------------------------------------------------------------------
// VE Endpoint resolution
// ---------------------------------------------------------------------------

/**
 * Get the VE endpoint URL.
 * Configured via VE_ENDPOINT environment variable.
 * This is a one-line .env change to swap staging → production → custom domain.
 */
function getVeEndpoint() {
  const endpoint = process.env.VE_ENDPOINT || readEnvValue('VE_ENDPOINT');
  if (!endpoint) {
    throw new Error(
      'VE_ENDPOINT not configured. Set VE_ENDPOINT in environment or CROCbox .env file.\n' +
      'Staging: https://opnli-ve-staging.fly.dev\n' +
      'Production: https://ve.opn.li'
    );
  }
  // Strip trailing slash for consistency
  return endpoint.replace(/\/+$/, '');
}

// ---------------------------------------------------------------------------
// Cryptographic utilities
// ---------------------------------------------------------------------------

/**
 * Generate an Ed25519 keypair for agent enrollment.
 * The public key is sent to the VE. The private key is stored locally
 * for future request signing (post-v1).
 */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

/**
 * Compute request_hash per VE Requirements Section 2:
 * SHA-256 of agent_id + card_id + operation_type + session_id + timestamp
 * 
 * This is a concatenation hash — fields are joined directly.
 * The VE validates this on receipt to confirm request integrity.
 */
function computeRequestHash(agent_id, card_id, operation_type, session_id, timestamp) {
  const payload = `${agent_id}${card_id}${operation_type}${session_id}${timestamp}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

// ---------------------------------------------------------------------------
// HTTP client with timeout and fail-closed behavior
// ---------------------------------------------------------------------------

/**
 * Make an HTTP request with strict timeout enforcement.
 * 
 * CRITICAL: This uses AbortController for timeout. When the timeout fires,
 * the request is aborted and the function returns a fail-closed result.
 * There is no "maybe" — timeout = denied.
 */
async function httpRequest(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const body = await response.json();

    return {
      ok: response.ok,
      status: response.status,
      body
    };
  } catch (err) {
    clearTimeout(timeoutId);

    if (err.name === 'AbortError') {
      return {
        ok: false,
        status: 408,
        body: { decision: 'denied', reason: 'VE request timed out — fail-closed', decision_id: null },
        timedOut: true
      };
    }

    // Network error, DNS failure, connection refused — all fail closed
    return {
      ok: false,
      status: 0,
      body: { decision: 'denied', reason: `VE unreachable: ${err.message} — fail-closed`, decision_id: null },
      networkError: true
    };
  }
}

/**
 * Exponential backoff with jitter for 429 retry.
 * Jitter prevents thundering herd when multiple CROCbox instances hit rate limits.
 */
function backoffDelay(attempt) {
  const base = BASE_BACKOFF_MS * Math.pow(2, attempt);
  const capped = Math.min(base, MAX_BACKOFF_MS);
  const jitter = Math.random() * capped * 0.5; // 0-50% jitter
  return capped + jitter;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Public API: enroll()
// ---------------------------------------------------------------------------

/**
 * Register a new agent with the Verification Endpoint.
 * 
 * Called during CROCbox first-run setup. This is the step that converts
 * "CROCbox running locally" into "a node on the Trust Network."
 * 
 * On success: writes VE_AGENT_ID and VE_CARD_ID to the CROCbox .env file.
 * On failure: throws with a human-readable message for the UI.
 * 
 * @param {string} opnli_account_id — The user's Opn.li account identifier
 * @param {string} rental_ski_level — beginner | intermediate | expert | partner
 * @returns {object} The full enrollment response from the VE
 */
async function enroll(opnli_account_id, rental_ski_level) {
  if (!opnli_account_id || typeof opnli_account_id !== 'string') {
    throw new Error('opnli_account_id is required and must be a string');
  }

  const validLevels = ['beginner', 'intermediate', 'expert', 'partner'];
  if (!validLevels.includes(rental_ski_level)) {
    throw new Error(`rental_ski_level must be one of: ${validLevels.join(', ')}`);
  }

  const veEndpoint = getVeEndpoint();
  const { publicKey, privateKey } = generateKeypair();

  const payload = {
    opnli_account_id,
    agent_type: AGENT_TYPE,
    agent_version: CROCBOX_VERSION,
    rental_ski_level,
    public_key: publicKey
  };

  const result = await httpRequest(
    `${veEndpoint}/v1/enroll`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    },
    ENROLL_TIMEOUT_MS
  );

  if (!result.ok) {
    const reason = result.body?.reason || result.body?.error || `HTTP ${result.status}`;
    throw new Error(`VE enrollment failed: ${reason}`);
  }

  // Success — store credentials in .env
  const response = result.body;

  if (response.agent_id) {
    writeEnvValue('VE_AGENT_ID', response.agent_id);
  }
  if (response.card_id) {
    writeEnvValue('VE_CARD_ID', response.card_id);
  }

  // Store the private key for future request signing (post-v1)
  // The public key is now registered with the VE
  const supportDir = path.dirname(getEnvPath());
  const keyPath = path.join(supportDir, 'agent_key.pem');
  fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });

  return response;
}

// ---------------------------------------------------------------------------
// Public API: verify()
// ---------------------------------------------------------------------------

/**
 * Verify a CARD operation with the Verification Endpoint.
 * 
 * Called by the CARD Proxy before every sensitive action. This is the
 * consent gate — the function that makes every consent decision enforceable
 * across the Trust Network.
 * 
 * CRITICAL INVARIANT: 3-second timeout. Timeout = denied. No exceptions.
 * This is fail-closed behavior. CROCbox never fails open.
 * 
 * Implements exponential backoff with jitter on 429 (rate limit) responses.
 * 
 * @param {string} operation_type — web_search | filesystem_read | filesystem_write | shell_exec | api_call
 * @param {string} card_id — The CARD identifier (from .env VE_CARD_ID or parameter)
 * @param {string} session_id — The CROCbox session identifier
 * @returns {object} { decision, decision_id, reason, expires_at, ve_version }
 */
async function verify(operation_type, card_id, session_id) {
  const validOps = ['web_search', 'filesystem_read', 'filesystem_write', 'shell_exec', 'api_call'];
  if (!validOps.includes(operation_type)) {
    return {
      decision: 'denied',
      decision_id: null,
      reason: `Invalid operation_type: ${operation_type}`,
      source: 'client_validation'
    };
  }

  // Read stored credentials from .env
  const agent_id = process.env.VE_AGENT_ID || readEnvValue('VE_AGENT_ID');
  if (!agent_id) {
    return {
      decision: 'denied',
      decision_id: null,
      reason: 'Agent not enrolled — VE_AGENT_ID not found in .env',
      source: 'client_validation'
    };
  }

  // Use provided card_id, fall back to .env
  const resolved_card_id = card_id || process.env.VE_CARD_ID || readEnvValue('VE_CARD_ID');
  if (!resolved_card_id) {
    return {
      decision: 'denied',
      decision_id: null,
      reason: 'No card_id available — VE_CARD_ID not found in .env',
      source: 'client_validation'
    };
  }

  if (!session_id || typeof session_id !== 'string') {
    return {
      decision: 'denied',
      decision_id: null,
      reason: 'session_id is required',
      source: 'client_validation'
    };
  }

  const veEndpoint = getVeEndpoint();
  const timestamp = new Date().toISOString();
  const request_hash = computeRequestHash(agent_id, resolved_card_id, operation_type, session_id, timestamp);

  const payload = {
    agent_id,
    card_id: resolved_card_id,
    operation_type,
    session_id,
    timestamp,
    request_hash
  };

  // Retry loop for 429 responses with exponential backoff + jitter
  for (let attempt = 0; attempt <= MAX_RETRIES_429; attempt++) {
    const result = await httpRequest(
      `${veEndpoint}/v1/verify`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      },
      VERIFY_TIMEOUT_MS
    );

    // Timeout — fail closed immediately, no retry
    if (result.timedOut) {
      return {
        decision: 'denied',
        decision_id: null,
        reason: 'VE timeout — fail-closed. Operation denied.',
        source: 've_timeout'
      };
    }

    // Network error — fail closed immediately, no retry
    if (result.networkError) {
      return {
        decision: 'denied',
        decision_id: null,
        reason: result.body.reason,
        source: 've_network_error'
      };
    }

    // 429 — rate limited, back off and retry
    if (result.status === 429 && attempt < MAX_RETRIES_429) {
      const delay = backoffDelay(attempt);
      await sleep(delay);
      // Regenerate timestamp and hash for retry (replay protection)
      const retryTimestamp = new Date().toISOString();
      payload.timestamp = retryTimestamp;
      payload.request_hash = computeRequestHash(
        agent_id, resolved_card_id, operation_type, session_id, retryTimestamp
      );
      continue;
    }

    // 429 but exhausted retries — fail closed
    if (result.status === 429) {
      return {
        decision: 'denied',
        decision_id: null,
        reason: 'VE rate limit exceeded — retries exhausted. Operation denied.',
        source: 've_rate_limit'
      };
    }

    // 200 — decision returned (approved, denied, or revoked)
    if (result.ok) {
      return {
        decision: result.body.decision || 'denied',
        decision_id: result.body.decision_id || null,
        reason: result.body.reason || null,
        expires_at: result.body.expires_at || null,
        ve_version: result.body.ve_version || null,
        source: 've_response'
      };
    }

    // 400, 401, 500 — fail closed, no retry
    return {
      decision: 'denied',
      decision_id: null,
      reason: result.body?.reason || result.body?.error || `VE returned HTTP ${result.status}`,
      source: `ve_error_${result.status}`
    };
  }

  // Should not reach here, but if it does — fail closed
  return {
    decision: 'denied',
    decision_id: null,
    reason: 'Unexpected state — fail-closed',
    source: 'client_error'
  };
}

// ---------------------------------------------------------------------------
// Public API: checkStatus()
// ---------------------------------------------------------------------------

/**
 * Check agent standing with the VE.
 * Called on CROCbox startup before accepting user input.
 * 
 * If the agent is not in good standing (revoked, suspended, unknown),
 * CROCbox should inform the user and prevent CARD operations.
 * 
 * @param {string} agent_id — The VE-assigned agent identifier (optional, reads from .env)
 * @returns {object} { status, agent_id, reason }
 */
async function checkStatus(agent_id) {
  const resolved_agent_id = agent_id || process.env.VE_AGENT_ID || readEnvValue('VE_AGENT_ID');

  if (!resolved_agent_id) {
    return {
      status: 'not_enrolled',
      agent_id: null,
      reason: 'No agent_id found — CROCbox has not been enrolled with the Trust Network'
    };
  }

  const veEndpoint = getVeEndpoint();

  const result = await httpRequest(
    `${veEndpoint}/v1/status/${encodeURIComponent(resolved_agent_id)}`,
    {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    },
    STATUS_TIMEOUT_MS
  );

  if (result.timedOut || result.networkError) {
    return {
      status: 'unreachable',
      agent_id: resolved_agent_id,
      reason: 'Trust Network temporarily unavailable. Running in local mode.'
    };
  }

  if (result.ok) {
    return {
      status: result.body.status || 'unknown',
      agent_id: resolved_agent_id,
      allowed_ops: result.body.allowed_ops || [],
      rental_ski_level: result.body.rental_ski_level || null,
      reason: result.body.reason || null
    };
  }

  // 401 — agent not recognized
  if (result.status === 401) {
    return {
      status: 'not_recognized',
      agent_id: resolved_agent_id,
      reason: 'Agent not recognized by Trust Network — re-enrollment may be required'
    };
  }

  return {
    status: 'error',
    agent_id: resolved_agent_id,
    reason: result.body?.reason || `VE returned HTTP ${result.status}`
  };
}

// ---------------------------------------------------------------------------
// Module exports
// ---------------------------------------------------------------------------

module.exports = {
  enroll,
  verify,
  checkStatus,
  // Exported for testing only — not part of the public DevKit API
  _internal: {
    computeRequestHash,
    readEnvValue,
    writeEnvValue,
    getVeEndpoint,
    getEnvPath
  }
};
