/**
 * ve_level_sync.js — B.4.5: Rental Ski Level Change Sync
 * 
 * Integration point: CROCbox Settings (dashboard/server.js)
 * 
 * When the user changes their Rental Ski level in CROCbox Settings,
 * this module syncs the change with the VE via PATCH /v1/enroll/{agent_id}.
 * 
 * CRITICAL INVARIANT: The local .env is updated ONLY after the VE 
 * confirms the update. If the VE update fails, the level change does 
 * not take effect locally. The user sees an error message.
 * 
 * This prevents a state where CROCbox thinks it's at Expert level
 * but the VE still has it at Beginner — which would cause every
 * Expert-level operation to be denied by the VE.
 * 
 * API route to add to server.js:
 *   PATCH /api/ve/level
 *   Body: { rental_ski_level }
 *   Returns: { success, old_level, new_level, allowed_ops, error }
 * 
 * @see OPN_ENG_VE-Requirements_14MAR26_v1.0, Section 9 (ENG-VE-03)
 * @see OPN_ENG_v07_BuildSpec_13MAR26.md, WP-5 (Graduated Consent)
 */

'use strict';

const veClient = require('./card_ve_client.js');

const VALID_LEVELS = ['beginner', 'intermediate', 'expert', 'partner'];

/**
 * Sync a Rental Ski level change with the Trust Network.
 * 
 * Flow:
 *   1. Read current agent_id from .env
 *   2. Read current level from .env
 *   3. Call PATCH /v1/enroll/{agent_id} with new level
 *   4. On VE success → update CROC_LEVEL in .env → return success
 *   5. On VE failure → do NOT update .env → return error
 * 
 * @param {string} newLevel — beginner | intermediate | expert | partner
 * @returns {object} { success, old_level, new_level, allowed_ops, error }
 */
async function syncLevelChange(newLevel) {
  // Validate input
  if (!VALID_LEVELS.includes(newLevel)) {
    return {
      success: false,
      old_level: null,
      new_level: null,
      allowed_ops: [],
      error: `Invalid level: ${newLevel}. Must be one of: ${VALID_LEVELS.join(', ')}`
    };
  }

  // Read current state from .env
  const agentId = process.env.VE_AGENT_ID || veClient._internal.readEnvValue('VE_AGENT_ID');
  if (!agentId) {
    return {
      success: false,
      old_level: null,
      new_level: null,
      allowed_ops: [],
      error: 'Agent not enrolled — cannot change level. Enroll with the Trust Network first.'
    };
  }

  const currentLevel = process.env.CROC_LEVEL || veClient._internal.readEnvValue('CROC_LEVEL') || 'beginner';

  // No-op if level is unchanged
  if (currentLevel === newLevel) {
    return {
      success: true,
      old_level: currentLevel,
      new_level: newLevel,
      allowed_ops: [],
      error: null,
      message: 'Level unchanged'
    };
  }

  // Call VE to update the level
  const veEndpoint = process.env.VE_ENDPOINT || veClient._internal.readEnvValue('VE_ENDPOINT');
  if (!veEndpoint) {
    return {
      success: false,
      old_level: currentLevel,
      new_level: null,
      allowed_ops: [],
      error: 'VE_ENDPOINT not configured. Cannot sync level change.'
    };
  }

  const endpoint = veEndpoint.replace(/\/+$/, '');
  const url = `${endpoint}/v1/enroll/${encodeURIComponent(agentId)}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s for level change

    const response = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rental_ski_level: newLevel }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const body = await response.json().catch(() => ({}));

    if (!response.ok) {
      const reason = body.reason || body.error || body.message || `HTTP ${response.status}`;
      return {
        success: false,
        old_level: currentLevel,
        new_level: null,
        allowed_ops: [],
        error: `Could not update Trust Network — level unchanged. ${reason}`
      };
    }

    // VE confirmed the update — NOW update local .env
    veClient._internal.writeEnvValue('CROC_LEVEL', newLevel);

    // Also update process.env for current session
    process.env.CROC_LEVEL = newLevel;

    return {
      success: true,
      old_level: currentLevel,
      new_level: newLevel,
      allowed_ops: body.allowed_ops || [],
      error: null
    };
  } catch (err) {
    if (err.name === 'AbortError') {
      return {
        success: false,
        old_level: currentLevel,
        new_level: null,
        allowed_ops: [],
        error: 'Could not update Trust Network — request timed out. Level unchanged. Try again or check your connection.'
      };
    }

    return {
      success: false,
      old_level: currentLevel,
      new_level: null,
      allowed_ops: [],
      error: `Could not update Trust Network — level unchanged. ${err.message}`
    };
  }
}

/**
 * Express/HTTP route handler for level change.
 * 
 * Add to server.js:
 *   const veLevelSync = require('../ve_level_sync.js');
 *   app.patch('/api/ve/level', veLevelSync.handleLevelChangeRequest);
 *   // Or for compatibility: app.post('/api/ve/level', ...)
 */
async function handleLevelChangeRequest(req, res) {
  try {
    // Parse body
    let body = req.body;
    if (!body && req.on) {
      body = await new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => data += chunk);
        req.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(e); }
        });
        req.on('error', reject);
      });
    }

    const { rental_ski_level } = body || {};

    if (!rental_ski_level) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'rental_ski_level is required' }));
      return;
    }

    const result = await syncLevelChange(rental_ski_level);

    const statusCode = result.success ? 200 : 502;
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, error: `Internal error: ${err.message}` }));
  }
}

module.exports = {
  syncLevelChange,
  handleLevelChangeRequest,
  VALID_LEVELS
};
