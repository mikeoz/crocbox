/**
 * @opnli/atl-devkit — Audit Logger
 * 
 * Append-only JSONL audit log with SHA-256 hash chain.
 * Every consent decision is recorded with timestamp, action, target,
 * result, reason, and a cryptographic link to the previous entry.
 * 
 * Tamper-evident: modifying any entry breaks the hash chain.
 * Honest disclosure: tamper-evident, not tamper-proof (INV-16).
 * 
 * Extracted from CROCbox ws-proxy.js — proven in production with
 * 100+ entries verified in live testing.
 * 
 * @see OPN_ENG_CROC-E2E-Invariants_13MAR26_v2, INV-8, INV-16
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Create an audit logger that writes to the specified path.
 * 
 * @param {string} logPath — Absolute path to the JSONL audit log file.
 * @returns {object} — { writeEntry, verifyChain }
 */
function createAuditLogger(logPath) {
  // Ensure the directory exists
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  /**
   * Append a consent decision to the audit log.
   * 
   * @param {object} opts
   * @param {string} opts.holdId — Unique identifier for this consent hold
   * @param {string} opts.runId — Agent run identifier
   * @param {string} opts.decision — 'allow' | 'deny' | 'timeout'
   * @param {string} opts.shield — 'yellow' | 'green'
   * @param {number} opts.gapSize — Seq-gap size (Yellow) or 0 (Green)
   * @param {number} opts.eventCount — Number of held events
   * @param {object} [opts.extra] — Additional fields to include
   * @returns {object} — The written entry (with hash)
   */
  function writeEntry(opts) {
    const { holdId, runId, decision, shield, gapSize, eventCount, extra } = opts;

    // Read last hash from file
    let prevHash = 'genesis';
    try {
      const content = fs.readFileSync(logPath, 'utf8').trim();
      if (content.length > 0) {
        const lines = content.split('\n');
        const lastEntry = JSON.parse(lines[lines.length - 1]);
        prevHash = lastEntry.hash || 'genesis';
      }
    } catch (e) { /* file may not exist yet — genesis */ }

    const reasonMap = {
      'allow': 'user-consent',
      'deny': 'user-deny',
      'timeout': 'user-timeout'
    };
    const resultMap = {
      'allow': 'allowed',
      'deny': 'blocked',
      'timeout': 'blocked'
    };

    const entry = {
      timestamp: new Date().toISOString(),
      action: shield + '-shield',
      target: 'agent-event-stream',
      result: resultMap[decision] || 'blocked',
      reason: reasonMap[decision] || 'unknown',
      detail: 'gap=' + gapSize + ' events-held=' + eventCount + ' holdId=' + holdId,
      decision_id: holdId,
      shield: shield,
      runId: runId,
      prev_hash: prevHash,
      ...(extra || {})
    };

    const entryStr = JSON.stringify(entry);
    entry.hash = crypto.createHash('sha256').update(entryStr + prevHash).digest('hex');

    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
    return entry;
  }

  /**
   * Verify the hash chain integrity of the audit log.
   * 
   * @returns {object} — { valid: boolean, entries: number, brokenAt: number|null }
   */
  function verifyChain() {
    let content;
    try {
      content = fs.readFileSync(logPath, 'utf8').trim();
    } catch (e) {
      return { valid: true, entries: 0, brokenAt: null };
    }

    if (content.length === 0) {
      return { valid: true, entries: 0, brokenAt: null };
    }

    const lines = content.split('\n');
    let expectedPrevHash = 'genesis';

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry = JSON.parse(lines[i]);

        // Check prev_hash links to previous entry
        if (entry.prev_hash !== expectedPrevHash) {
          return { valid: false, entries: lines.length, brokenAt: i };
        }

        // Recompute hash: strip hash field, serialize, hash with prev_hash
        const storedHash = entry.hash;
        const stripped = { ...entry };
        delete stripped.hash;
        const recomputed = crypto.createHash('sha256')
          .update(JSON.stringify(stripped) + expectedPrevHash)
          .digest('hex');

        if (storedHash !== recomputed) {
          return { valid: false, entries: lines.length, brokenAt: i };
        }

        expectedPrevHash = storedHash;
      } catch (e) {
        return { valid: false, entries: lines.length, brokenAt: i };
      }
    }

    return { valid: true, entries: lines.length, brokenAt: null };
  }

  return { writeEntry, verifyChain };
}

module.exports = { createAuditLogger };
