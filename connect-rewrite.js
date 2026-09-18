/**
 * connect-rewrite.js — Connect Rewrite Interface for CROCbox
 *
 * Adapts the client's WebSocket connect request for proxy pass-through.
 * The specific rewrite strategy depends on the upstream gateway's auth model.
 *
 * This is the open-source stub. Replace with your own implementation
 * if your gateway requires a different authentication translation.
 *
 * @param {object} msg - The parsed WebSocket connect request message
 * @param {string} token - The gateway auth token
 * @param {string} scenario - Installation scenario: 'NHB' | 'EXISTING_OC' | 'UPGRADE'
 * @returns {object} The rewritten message, ready to JSON.stringify and send
 */
function rewriteConnectForProxy(msg, token, scenario) {
  // Default: inject auth token, preserve client type unchanged
  if (!msg.params.auth || !msg.params.auth.token) {
    msg.params.auth = { token: token };
  }
  return msg;
}

module.exports = { rewriteConnectForProxy };
