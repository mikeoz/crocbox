/**
 * ve_audit_logger.js — B.4.2: Audit Log VE Integration
 * 
 * Closes GAP-1 from E2E Invariants v2: "Phase 2 tool-call consent 
 * decisions are enforced but not audited."
 * 
 * This module extends the existing writeAuditEntry() pattern to include
 * the VE decision_id field. Every audit log entry now links the local 
 * consent decision to the VE verification record.
 * 
 * Integration point: Called from the CARD Proxy consent handler and 
 * from server.js after each consent decision.
 * 
 * The audit log format is JSON-lines (crocbox-audit.jsonl) with SHA-256
 * hash chain per E2E Invariants Section 9.
 * 
 * @see OPN_ENG_VE-Requirements_14MAR26_v1.0, Section 9 (ENG-VE-02)
 * @see OPN_ENG_CROC-E2E-Invariants_13MAR26_v2.md, Section 9 (Audit Log Schema)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Audit log file resolution
// ---------------------------------------------------------------------------

/**
 * Get the audit log file path.
 * Per E2E Invariants: ~/opnli/crocbox/logs/crocbox-audit.jsonl
 * Override with CROCBOX_AUDIT_PATH for testing.
 */
function getAuditLogPath() {
  if (process.env.CROCBOX_AUDIT_PATH) {
    return process.env.CROCBOX_AUDIT_PATH;
  }
  const homeDir = process.env.HOME || process.env.USERPROFILE || '/tmp';
  return path.join(homeDir, 'opnli', 'crocbox', 'logs', 'crocbox-audit.jsonl');
}

// ---------------------------------------------------------------------------
// Hash chain management
// ---------------------------------------------------------------------------

/**
 * Read the last entry's hash from the audit log.
 * Returns 'genesis' if the file is empty or doesn't exist.
 */
function getLastHash() {
  const logPath = getAuditLogPath();
  try {
    const content = fs.readFileSync(logPath, 'utf8').trim();
    if (!content) return 'genesis';

    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length === 0) return 'genesis';

    const lastLine = lines[lines.length - 1];
    const lastEntry = JSON.parse(lastLine);
    return lastEntry.hash || 'genesis';
  } catch {
    return 'genesis';
  }
}

/**
 * Compute SHA-256 hash for the hash chain.
 * Per E2E Invariants: hash of this entry + previous hash.
 */
function computeEntryHash(entryData, prevHash) {
  const payload = JSON.stringify(entryData) + prevHash;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

// ---------------------------------------------------------------------------
// Audit entry writer
// ---------------------------------------------------------------------------

/**
 * Write an audit log entry with VE decision linkage.
 * 
 * This function extends the existing audit log format with:
 *   - decision_id: Links to the VE verification record
 *   - ve_decision: The VE's trust decision (approved/denied/revoked)
 *   - ve_source: Where the VE decision came from
 * 
 * These fields are null/absent for entries that don't involve VE
 * (e.g., demo mode, local-only mode).
 * 
 * @param {object} entry — The audit entry fields
 * @param {string} entry.action — Action type (web_search, filesystem-read, etc.)
 * @param {string} entry.target — What was targeted (URL, path, etc.)
 * @param {string} entry.result — Outcome (intercepted, allowed, blocked, completed)
 * @param {string} entry.reason — Why (user-consent, user-deny, ve-denied, etc.)
 * @param {string} [entry.detail] — Additional context
 * @param {string} [entry.source] — 'magic-demo' for Phase 1 entries
 * @param {boolean} [entry.demo] — true for demonstration-mode entries
 * @param {string} [entry.decision_id] — VE decision identifier (NEW — B.4.2)
 * @param {string} [entry.ve_decision] — VE trust decision (NEW — B.4.2)
 * @param {string} [entry.ve_source] — VE decision source (NEW — B.4.2)
 * @param {string} [entry.session_id] — CROCbox session identifier
 */
function writeAuditEntry(entry) {
  const logPath = getAuditLogPath();
  const logDir = path.dirname(logPath);

  // Ensure log directory exists
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const prevHash = getLastHash();

  // Build the entry data (fields that go into the hash)
  const entryData = {
    timestamp: new Date().toISOString(),
    action: entry.action,
    target: entry.target,
    result: entry.result,
    reason: entry.reason,
    detail: entry.detail || null
  };

  // Add optional fields
  if (entry.source) entryData.source = entry.source;
  if (entry.demo) entryData.demo = entry.demo;

  // VE integration fields (B.4.2 — NEW)
  if (entry.decision_id) entryData.decision_id = entry.decision_id;
  if (entry.ve_decision) entryData.ve_decision = entry.ve_decision;
  if (entry.ve_source) entryData.ve_source = entry.ve_source;
  if (entry.session_id) entryData.session_id = entry.session_id;

  // Compute hash chain
  const hash = computeEntryHash(entryData, prevHash);

  // Build the full log line
  const logEntry = {
    ...entryData,
    hash,
    prevHash
  };

  // Append to log file
  const logLine = JSON.stringify(logEntry) + '\n';
  fs.appendFileSync(logPath, logLine, 'utf8');

  return logEntry;
}

/**
 * Create a VE-enriched audit entry from a consent decision.
 * 
 * This is the convenience function that the CARD Proxy consent handler
 * calls after both VE verification and local consent are complete.
 * 
 * @param {object} params
 * @param {string} params.action — CROCbox action type
 * @param {string} params.target — Action target
 * @param {string} params.localDecision — User's local decision (allow/deny/timeout)
 * @param {object} params.veResult — Result from ve_consent_gate.checkVePermission()
 * @param {string} [params.detail] — Additional context
 * @param {string} [params.sessionId] — Session identifier
 */
function writeConsentAuditEntry(params) {
  const { action, target, localDecision, veResult, detail, sessionId } = params;

  // Determine the final result and reason
  let result, reason;

  if (veResult && !veResult.allowed) {
    // VE denied — action was blocked at Trust Network level
    result = 'blocked';
    reason = 've-denied';
  } else if (localDecision === 'allow') {
    result = 'allowed';
    reason = 'user-consent';
  } else if (localDecision === 'deny') {
    result = 'blocked';
    reason = 'user-deny';
  } else if (localDecision === 'timeout') {
    result = 'blocked';
    reason = 'user-timeout';
  } else if (localDecision === 'no-dashboard') {
    result = 'blocked';
    reason = 'user-no-dashboard';
  } else if (localDecision === 'session-grant') {
    result = 'allowed';
    reason = 'session-grant';
  } else {
    result = 'blocked';
    reason = localDecision || 'unknown';
  }

  return writeAuditEntry({
    action,
    target,
    result,
    reason,
    detail: detail || null,
    decision_id: veResult?.decision_id || null,
    ve_decision: veResult?.decision || null,
    ve_source: veResult?.source || null,
    session_id: sessionId || null
  });
}

/**
 * Verify the hash chain integrity of the audit log.
 * Returns { valid: boolean, entries: number, errors: string[] }
 */
function verifyHashChain() {
  const logPath = getAuditLogPath();
  const errors = [];

  try {
    const content = fs.readFileSync(logPath, 'utf8').trim();
    if (!content) return { valid: true, entries: 0, errors: [] };

    const lines = content.split('\n').filter(l => l.trim());
    let expectedPrevHash = 'genesis';

    for (let i = 0; i < lines.length; i++) {
      const entry = JSON.parse(lines[i]);

      // Check prevHash linkage
      if (entry.prevHash !== expectedPrevHash) {
        errors.push(`Entry ${i}: prevHash mismatch. Expected ${expectedPrevHash}, got ${entry.prevHash}`);
      }

      // Verify hash
      const { hash, prevHash, ...entryData } = entry;
      const expectedHash = computeEntryHash(entryData, prevHash);
      if (hash !== expectedHash) {
        errors.push(`Entry ${i}: hash mismatch. Expected ${expectedHash}, got ${hash}`);
      }

      expectedPrevHash = hash;
    }

    return { valid: errors.length === 0, entries: lines.length, errors };
  } catch (err) {
    return { valid: false, entries: 0, errors: [err.message] };
  }
}

module.exports = {
  writeAuditEntry,
  writeConsentAuditEntry,
  verifyHashChain,
  getAuditLogPath,
  // For testing
  _internal: {
    getLastHash,
    computeEntryHash
  }
};
