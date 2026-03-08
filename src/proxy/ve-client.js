/**
 * CROCbox VE Client
 *
 * Calls the CARD Verification Endpoint to check whether the agent
 * is authorized to perform actions. Returns the VE response or
 * throws on failure (which triggers fail-closed behavior).
 */

const https = require("https");
const http = require("http");

/**
 * Check agent authorization against the Verification Endpoint.
 *
 * @param {string} veUrl - Full URL of the VE (e.g., https://xxx.supabase.co/functions/v1/verify-card)
 * @param {string} apiKey - VERIFY_API_KEY
 * @param {string} agentId - Agent URN (e.g., urn:uuid:5b3a4df1-...)
 * @returns {Promise<Object>} VE response with entity_status, active_use_cards, etc.
 * @throws {Error} If VE is unreachable or returns non-200
 */
async function checkAuthorization(veUrl, apiKey, agentId) {
  const fullUrl = `${veUrl}?agent_id=${encodeURIComponent(agentId)}`;
  const urlObj = new URL(fullUrl);
  const transport = urlObj.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      req.destroy();
      reject(new Error("VE request timed out (10s)"));
    }, 10000);

    const req = transport.request(
      fullUrl,
      {
        method: "GET",
        headers: {
          "x-api-key": apiKey,
          Accept: "application/json",
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          clearTimeout(timeout);

          if (res.statusCode !== 200) {
            reject(
              new Error(
                `VE returned HTTP ${res.statusCode}: ${data.substring(0, 200)}`
              )
            );
            return;
          }

          try {
            const parsed = JSON.parse(data);
            resolve(parsed);
          } catch (err) {
            reject(new Error(`VE returned invalid JSON: ${err.message}`));
          }
        });
      }
    );

    req.on("error", (err) => {
      clearTimeout(timeout);
      reject(new Error(`VE unreachable: ${err.message}`));
    });

    req.end();
  });
}

// Cache VE results for a short window to avoid hammering the endpoint
const cache = new Map();
const CACHE_TTL_MS = 30000; // 30 seconds

async function checkAuthorizationCached(veUrl, apiKey, agentId) {
  const cacheKey = agentId;
  const cached = cache.get(cacheKey);

  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  const result = await checkAuthorization(veUrl, apiKey, agentId);
  cache.set(cacheKey, { result, timestamp: Date.now() });
  return result;
}

module.exports = { checkAuthorization, checkAuthorizationCached };
