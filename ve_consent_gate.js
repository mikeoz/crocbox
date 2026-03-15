/**
 * ve_consent_gate.js — B.4.1: VE Verification Gate
 * 
 * Integration point: CARD Proxy consent flow (src/proxy/index.js)
 * 
 * This module adds VE verification BEFORE the local consent prompt.
 * The flow becomes:
 * 
 *   1. Agent requests action (tool_use)
 *   2. CARD Proxy intercepts
 *   3. → NEW: VE verification (ve_consent_gate.js)
 *      - If VE denies → action blocked, user never sees consent prompt
 *      - If VE approves → proceed to local consent
 *      - If VE unreachable → fail-closed, action blocked
 *   4. Local consent prompt (existing consent.js flow)
 *   5. User clicks Allow/Deny
 *   6. Action executes or blocks
 * 
 * Architecture: VE decides TRUST. User decides CONSENT. Both must approve.
 * 
 * @see OPN_ENG_VE-Requirements_14MAR26_v1.0, Section 9 (ENG-VE-01)
 * @see OPN_ENG_CROC-E2E-Invariants_13MAR26_v2.md, Section 8 (Two-Path Architecture)
 */

'use strict';

const veClient = require('./card_ve_client.js');
const crypto = require('crypto');

/**
 * Map CROCbox action types to VE operation_types.
 * 
 * CROCbox audit log uses: filesystem-read, filesystem-write, api_call, web_search, shell_exec, email
 * VE API uses: filesystem_read, filesystem_write, api_call, web_search, shell_exec
 * 
 * The mapping normalizes the hyphenated CROCbox names to the underscore VE names.
 */
const ACTION_TO_OPERATION = {
  'filesystem-read': 'filesystem_read',
  'filesystem-write': 'filesystem_write',
  'filesystem_read': 'filesystem_read',
  'filesystem_write': 'filesystem_write',
  'api_call': 'api_call',
  'web_search': 'web_search',
  'shell_exec': 'shell_exec',
  'email': 'api_call',       // email is an api_call from VE's perspective
  'safe': null                // safe actions don't need VE verification
};

/**
 * Generate a session ID for this CROCbox session.
 * Called once at startup, stored for the session duration.
 * Session IDs are used for session-grant tracking at Intermediate/Expert levels.
 */
let _sessionId = null;
function getSessionId() {
  if (!_sessionId) {
    _sessionId = `croc-session-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  }
  return _sessionId;
}

/**
 * Reset the session ID (called on CROCbox restart).
 */
function resetSession() {
  _sessionId = null;
}

/**
 * Check with the VE whether this action is permitted.
 * 
 * This is the gate function. It is called BEFORE the local consent prompt.
 * 
 * Returns an object with:
 *   - allowed: boolean — whether the VE permits this action
 *   - decision: string — 'approved', 'denied', or 'revoked'
 *   - decision_id: string|null — for audit log linkage (B.4.2)
 *   - reason: string|null — human-readable reason for denial
 *   - source: string — where the decision came from
 * 
 * CRITICAL: If this function returns allowed: false, the action MUST NOT
 * proceed to the local consent prompt. The VE has denied at the Trust
 * Network level. This is not a suggestion — it is enforcement.
 * 
 * @param {string} actionType — CROCbox action type (e.g., 'web_search', 'filesystem-read')
 * @param {string} [cardId] — CARD identifier (reads from .env if not provided)
 * @returns {object} { allowed, decision, decision_id, reason, source }
 */
async function checkVePermission(actionType, cardId) {
  // Map CROCbox action type to VE operation type
  const operationType = ACTION_TO_OPERATION[actionType];

  // Safe actions bypass VE verification
  if (operationType === null || operationType === undefined) {
    return {
      allowed: true,
      decision: 'approved',
      decision_id: null,
      reason: 'Safe action — VE verification not required',
      source: 'local_bypass'
    };
  }

  const sessionId = getSessionId();

  try {
    const result = await veClient.verify(operationType, cardId, sessionId);

    return {
      allowed: result.decision === 'approved',
      decision: result.decision,
      decision_id: result.decision_id,
      reason: result.reason,
      source: result.source,
      expires_at: result.expires_at,
      ve_version: result.ve_version
    };
  } catch (err) {
    // Any error = fail-closed
    return {
      allowed: false,
      decision: 'denied',
      decision_id: null,
      reason: `VE gate error: ${err.message} — fail-closed`,
      source: 've_gate_error'
    };
  }
}

/**
 * Check if the VE client is configured (agent is enrolled).
 * Used by the consent flow to decide whether to call the VE gate.
 * If not enrolled, the system runs in local-only mode.
 */
function isVeConfigured() {
  try {
    const agentId = process.env.VE_AGENT_ID || veClient._internal.readEnvValue('VE_AGENT_ID');
    const endpoint = process.env.VE_ENDPOINT || veClient._internal.readEnvValue('VE_ENDPOINT');
    return !!(agentId && endpoint);
  } catch {
    return false;
  }
}

module.exports = {
  checkVePermission,
  isVeConfigured,
  getSessionId,
  resetSession,
  ACTION_TO_OPERATION
};
