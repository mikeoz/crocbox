/**
 * ve_enrollment.js — B.4.3: First-Run VE Enrollment
 * 
 * Integration point: CROCbox first-run setup flow (dashboard/first-run.html,
 * dashboard/server.js)
 * 
 * After the user selects their Rental Ski level during first-run setup,
 * CROCbox calls enrollWithTrustNetwork() to register with the VE.
 * 
 * This is the step that converts "CROCbox running locally" into
 * "a node on the Trust Network."
 * 
 * Flow:
 *   1. User selects Rental Ski level (beginner/intermediate/expert)
 *   2. User enters or receives opnli_account_id
 *   3. → enrollWithTrustNetwork() called
 *   4. On success: VE_AGENT_ID, VE_CARD_ID written to .env → proceed to Magic Moment
 *   5. On failure: CROCbox runs in local mode → user can retry from Settings
 * 
 * API route to add to server.js:
 *   POST /api/ve/enroll
 *   Body: { opnli_account_id, rental_ski_level }
 *   Returns: { success, agent_id, card_id, allowed_ops, error }
 * 
 * @see OPN_ENG_VE-Requirements_14MAR26_v1.0, Section 9 (ENG-VE-01)
 * @see OPN_PM-Spec_FullCROC_13MAR26_v1.0, Section 4 (Magic Moment Onboarding)
 */

'use strict';

const veClient = require('./card_ve_client.js');

/**
 * Enroll this CROCbox instance with the Trust Network.
 * 
 * Called during first-run setup after the user selects their level.
 * On success, VE_AGENT_ID and VE_CARD_ID are stored in .env by card_ve_client.js.
 * 
 * @param {string} opnliAccountId — The user's Opn.li account identifier
 * @param {string} rentalSkiLevel — beginner | intermediate | expert
 * @returns {object} { success, agent_id, card_id, allowed_ops, ve_endpoint, error }
 */
async function enrollWithTrustNetwork(opnliAccountId, rentalSkiLevel) {
  try {
    const response = await veClient.enroll(opnliAccountId, rentalSkiLevel);

    return {
      success: true,
      agent_id: response.agent_id,
      card_id: response.card_id,
      allowed_ops: response.allowed_ops || [],
      ve_endpoint: response.ve_endpoint || null,
      enrolled_at: response.enrolled_at || new Date().toISOString(),
      error: null
    };
  } catch (err) {
    return {
      success: false,
      agent_id: null,
      card_id: null,
      allowed_ops: [],
      ve_endpoint: null,
      enrolled_at: null,
      error: err.message
    };
  }
}

/**
 * Check if this CROCbox instance is already enrolled.
 * Called during startup to skip enrollment if already done.
 */
function isEnrolled() {
  const agentId = process.env.VE_AGENT_ID || veClient._internal.readEnvValue('VE_AGENT_ID');
  const cardId = process.env.VE_CARD_ID || veClient._internal.readEnvValue('VE_CARD_ID');
  return !!(agentId && cardId);
}

/**
 * Get the current enrollment info from .env.
 * Returns null if not enrolled.
 */
function getEnrollmentInfo() {
  const agentId = process.env.VE_AGENT_ID || veClient._internal.readEnvValue('VE_AGENT_ID');
  const cardId = process.env.VE_CARD_ID || veClient._internal.readEnvValue('VE_CARD_ID');
  const level = process.env.CROC_LEVEL || veClient._internal.readEnvValue('CROC_LEVEL');
  const endpoint = process.env.VE_ENDPOINT || veClient._internal.readEnvValue('VE_ENDPOINT');

  if (!agentId) return null;

  return {
    agent_id: agentId,
    card_id: cardId,
    rental_ski_level: level || 'beginner',
    ve_endpoint: endpoint || null
  };
}

/**
 * Express/HTTP route handler for enrollment.
 * 
 * Add to server.js:
 *   const veEnrollment = require('../ve_enrollment.js');
 *   app.post('/api/ve/enroll', veEnrollment.handleEnrollRequest);
 * 
 * Or for non-Express HTTP server, call handleEnrollRequest(req, res).
 */
async function handleEnrollRequest(req, res) {
  try {
    // Parse body (handle both Express parsed body and raw HTTP)
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

    const { opnli_account_id, rental_ski_level } = body || {};

    if (!opnli_account_id) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'opnli_account_id is required' }));
      return;
    }

    if (!rental_ski_level || !['beginner', 'intermediate', 'expert', 'partner'].includes(rental_ski_level)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'rental_ski_level must be beginner, intermediate, expert, or partner' }));
      return;
    }

    const result = await enrollWithTrustNetwork(opnli_account_id, rental_ski_level);

    const statusCode = result.success ? 200 : 502;
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, error: `Internal error: ${err.message}` }));
  }
}

module.exports = {
  enrollWithTrustNetwork,
  isEnrolled,
  getEnrollmentInfo,
  handleEnrollRequest
};
