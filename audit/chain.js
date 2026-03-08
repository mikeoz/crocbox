/**
 * Audit Log Hash Chain — Tamper-Evident Integrity
 * 
 * Each audit log entry includes a SHA-256 hash of:
 * - Its own content
 * - The previous entry's hash
 * 
 * This creates a chain. If any entry is modified, the chain breaks.
 */

const crypto = require('crypto');

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function normalizeEntry(entry) {
  const content = {
    id: entry.id,
    timestamp: entry.timestamp || entry.created_at,
    action_type: entry.action_type || entry.action || entry.actionType,
    target: entry.target,
    result: entry.result,
    session_id: entry.session_id
  };
  return JSON.stringify(content, Object.keys(content).sort());
}

function computeEntryHash(entry, previousHash) {
  const content = normalizeEntry(entry);
  const dataToHash = previousHash ? `${previousHash}:${content}` : content;
  return sha256(dataToHash);
}

function verifyChain(entries) {
  if (!entries || entries.length === 0) {
    return {
      valid: true,
      message: 'No entries to verify',
      checkedCount: 0,
      breakPoint: null
    };
  }
  
  let previousHash = null;
  
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const expected = computeEntryHash(entry, previousHash);
    const actual = entry.entry_hash;
    
    if (actual && expected !== actual) {
      return {
        valid: false,
        message: `Chain broken at entry ${i + 1}`,
        checkedCount: i + 1,
        breakPoint: {
          index: i,
          entryId: entry.id,
          timestamp: entry.timestamp || entry.created_at
        }
      };
    }
    
    previousHash = actual || expected;
  }
  
  return {
    valid: true,
    message: `All ${entries.length} entries verified`,
    checkedCount: entries.length,
    breakPoint: null
  };
}

function createEntry(entryData, previousHash) {
  const entry = {
    ...entryData,
    id: entryData.id || crypto.randomUUID(),
    timestamp: entryData.timestamp || new Date().toISOString()
  };
  
  entry.entry_hash = computeEntryHash(entry, previousHash);
  entry.previous_hash = previousHash;
  
  return entry;
}

function getLastHash(entries) {
  if (!entries || entries.length === 0) return null;
  return entries[entries.length - 1].entry_hash;
}

module.exports = {
  sha256,
  normalizeEntry,
  computeEntryHash,
  verifyChain,
  createEntry,
  getLastHash
};
