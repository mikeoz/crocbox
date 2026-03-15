/**
 * ve_startup_check.js — B.4.4: Startup Agent Status Verification
 * 
 * Integration point: CROCbox launcher / dashboard server startup
 * (dashboard/server.js, src/proxy/index.js)
 * 
 * On every CROCbox launch, before accepting user input, this module
 * verifies the agent is still in good standing with the Trust Network.
 * 
 * Status outcomes:
 *   - 'active': Agent enrolled and in good standing. Full ATL operation.
 *   - 'not_enrolled': No agent_id found. CROCbox runs in local mode.
 *     User sees enrollment prompt.
 *   - 'revoked': Agent has been revoked. CARD operations blocked.
 *     User sees re-enrollment prompt.
 *   - 'not_recognized': Agent_id not found on VE. May need re-enrollment.
 *   - 'unreachable': VE cannot be reached. CROCbox runs in local mode
 *     with degraded trust. User sees "Trust Network temporarily unavailable."
 *   - 'error': Unexpected error. CROCbox runs in local mode.
 * 
 * IMPORTANT: An unreachable VE does NOT prevent CROCbox from running.
 * The user can still use CROCbox with local consent enforcement.
 * The VE gate (B.4.1) will fail-closed on individual operations,
 * but the app itself remains functional.
 * 
 * This is different from verify() fail-closed behavior:
 *   - verify() fail-closed: individual action denied (correct)
 *   - startup check: app still launches, surfaces status to user (correct)
 * 
 * @see OPN_ENG_VE-Requirements_14MAR26_v1.0, Section 9 (ENG-VE-01)
 */

'use strict';

const veClient = require('./card_ve_client.js');

/**
 * Check agent standing with the Trust Network.
 * 
 * Call this during CROCbox startup, after services are running
 * but before the dashboard opens to the user.
 * 
 * @returns {object} {
 *   status: 'active' | 'not_enrolled' | 'revoked' | 'not_recognized' | 'unreachable' | 'error',
 *   agent_id: string | null,
 *   message: string — human-readable status for the dashboard,
 *   allowed_ops: string[] — operations permitted at current level,
 *   canOperate: boolean — whether CARD operations should be allowed,
 *   localModeReason: string | null — why running in local mode (if applicable)
 * }
 */
async function performStartupCheck() {
  // First, check if we're even enrolled
  const agentId = process.env.VE_AGENT_ID || veClient._internal.readEnvValue('VE_AGENT_ID');

  if (!agentId) {
    return {
      status: 'not_enrolled',
      agent_id: null,
      message: 'Not connected to the Trust Network. Set up your account to enable network-verified consent.',
      allowed_ops: [],
      canOperate: true,   // Can still use CROCbox with local consent only
      localModeReason: 'Agent not enrolled'
    };
  }

  // Agent is enrolled — check standing with VE
  try {
    const result = await veClient.checkStatus(agentId);

    switch (result.status) {
      case 'active':
        return {
          status: 'active',
          agent_id: agentId,
          message: 'Connected to the Trust Network. All consent decisions are network-verified.',
          allowed_ops: result.allowed_ops || [],
          canOperate: true,
          localModeReason: null
        };

      case 'revoked':
        return {
          status: 'revoked',
          agent_id: agentId,
          message: 'Your agent has been revoked from the Trust Network. Contact support or re-enroll.',
          allowed_ops: [],
          canOperate: false,  // Cannot operate — revoked agents must not perform CARD operations
          localModeReason: 'Agent revoked by Trust Network'
        };

      case 'suspended':
        return {
          status: 'suspended',
          agent_id: agentId,
          message: 'Your agent is temporarily suspended. Contact support for details.',
          allowed_ops: [],
          canOperate: false,
          localModeReason: 'Agent suspended by Trust Network'
        };

      case 'not_recognized':
        return {
          status: 'not_recognized',
          agent_id: agentId,
          message: 'Agent not recognized by the Trust Network. You may need to re-enroll.',
          allowed_ops: [],
          canOperate: true,   // Allow local operation while user resolves
          localModeReason: 'Agent not recognized — re-enrollment may be needed'
        };

      case 'unreachable':
        return {
          status: 'unreachable',
          agent_id: agentId,
          message: 'Trust Network temporarily unavailable. Running in local mode. Your consent decisions are recorded locally.',
          allowed_ops: [],
          canOperate: true,   // Local mode — consent works locally
          localModeReason: 'Trust Network unreachable'
        };

      default:
        return {
          status: 'error',
          agent_id: agentId,
          message: `Unexpected status from Trust Network: ${result.status}. Running in local mode.`,
          allowed_ops: [],
          canOperate: true,
          localModeReason: `Unexpected VE status: ${result.status}`
        };
    }
  } catch (err) {
    return {
      status: 'error',
      agent_id: agentId,
      message: `Trust Network check failed: ${err.message}. Running in local mode.`,
      allowed_ops: [],
      canOperate: true,
      localModeReason: `Startup check error: ${err.message}`
    };
  }
}

/**
 * Express/HTTP route handler for startup status.
 * 
 * The dashboard calls this on load to display Trust Network status.
 * 
 * Add to server.js:
 *   const veStartup = require('../ve_startup_check.js');
 *   app.get('/api/ve/status', veStartup.handleStatusRequest);
 */
async function handleStatusRequest(req, res) {
  try {
    const result = await performStartupCheck();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'error',
      message: `Status check failed: ${err.message}`,
      canOperate: true,
      localModeReason: err.message
    }));
  }
}

module.exports = {
  performStartupCheck,
  handleStatusRequest
};
