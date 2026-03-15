/**
 * CROCbox CARD Proxy — Module 1
 *
 * HTTP reverse proxy that sits between OpenClaw (port 18789) and
 * the outside world. Intercepts sensitive actions, checks the
 * Verification Endpoint for authorization, and manages consent.
 *
 * Architecture:
 *   Internet <-- CARD Proxy (:18790) <-- OpenClaw Gateway (:18789)
 *                     |
 *              Verification Endpoint
 *           (Lovable Supabase)
 *
 * Fail-closed: if VE is unreachable, all actions are blocked.
 */

const http = require("http");
const httpProxy = require("http-proxy");
const { WebSocketServer } = require("ws");
const { classifyAction, ACTION_TYPES } = require("./classify");

// Load .env before CONFIG is built
require("dotenv").config();

const { checkAuthorization } = require("./ve-client");
const { AuditLogger } = require("./audit-logger");
const { ConsentManager } = require("./consent");
const veClient = require("../../card_ve_client");

// ── Configuration ─────────────────────────────────────────────────
const CONFIG = {
  proxyPort: parseInt(process.env.CROCBOX_PROXY_PORT || "18790"),
  gatewayHost: process.env.OPENCLAW_HOST || "127.0.0.1",
  gatewayPort: parseInt(process.env.OPENCLAW_PORT || "18789"),
  veUrl: process.env.VERIFY_CARD_URL,
  veApiKey: process.env.VERIFY_API_KEY,
  agentId: process.env.CROCBOX_AGENT_ID,
  consentTimeoutMs: parseInt(process.env.CROCBOX_CONSENT_TIMEOUT || "300000"), // 5 min
  dashboardPort: parseInt(process.env.CROCBOX_DASHBOARD_PORT || "3000"),
};

// ── Validate required config ──────────────────────────────────────
function validateConfig() {
  const missing = [];
  if (!CONFIG.veUrl) missing.push("VERIFY_CARD_URL");
  if (!CONFIG.veApiKey) missing.push("VERIFY_API_KEY");
  if (!CONFIG.agentId) missing.push("CROCBOX_AGENT_ID");
  if (missing.length > 0) {
    console.error(`\n  CROCbox CARD Proxy — Missing configuration:`);
    missing.forEach((k) => console.error(`    - ${k}`));
    console.error(`\n  Set these in your .env file or environment.\n`);
    process.exit(1);
  }
}

// ── Audit Logger ──────────────────────────────────────────────────
const audit = new AuditLogger();

// ── Consent Manager ───────────────────────────────────────────────
const consent = new ConsentManager(CONFIG.consentTimeoutMs);

// ── Proxy Server ──────────────────────────────────────────────────
const proxy = httpProxy.createProxyServer({
  target: `http://${CONFIG.gatewayHost}:${CONFIG.gatewayPort}`,
  ws: true,
});

proxy.on("error", (err, req, res) => {
  console.error(`  Proxy error: ${err.message}`);
  if (res && res.writeHead) {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "CROCbox: upstream unavailable" }));
  }
});

// ── Action Interceptor ────────────────────────────────────────────
async function handleRequest(req, res) {
  if (req.url === "/crocbox/health") { res.writeHead(200, {"Content-Type":"application/json"}); res.end(JSON.stringify({status:"ok"})); return; }

    if (req.url === "/crocbox/magic-consent" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", async () => {
        let action;
        try { action = JSON.parse(body); }
        catch { action = { type: "filesystem", target: "~/Desktop", summary: "Magic demo" }; }
        console.log("  [MAGIC-CONSENT] Request for " + action.type + ": " + action.target);
        audit.log({ action: action.type, target: action.target, result: "intercepted", reason: "magic-demo-request" });

        // ── B.4 VE Gate: verify before consent ──
        let veDecision = null;
        try {
          const sessionId = process.env.CROCBOX_SESSION_ID || "session-" + Date.now();
          veDecision = await veClient.verify(action.type, null, sessionId);
          console.log("  [VE] verify() returned: " + veDecision.decision + (veDecision.decision_id ? " (id: " + veDecision.decision_id + ")" : ""));
        } catch (veErr) {
          console.log("  [VE] verify() error (fail-closed): " + veErr.message);
          veDecision = { decision: "denied", decision_id: null, reason: "ve-error", source: "ve_error" };
        }
        if (veDecision.decision !== "approved") {
          audit.log({ action: action.type, target: action.target, result: "blocked", reason: "ve-denied", detail: veDecision.reason || "VE did not approve", decision_id: veDecision.decision_id || null });
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ decision: "deny", reason: "ve-denied", detail: veDecision.reason }));
          return;
        }
        // ── VE approved — proceed to local consent ──

        const decision = await consent.requestConsent({ type: action.type, target: action.target, summary: action.summary });
        audit.log({ action: action.type, target: action.target, result: (decision === "allow" || decision === "remember") ? "allowed" : "blocked", reason: "magic-demo-consent:" + decision, decision_id: veDecision ? veDecision.decision_id : null });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ decision }));
      });
      return;
    }
  const action = classifyAction(req);

  // Safe actions pass through immediately
  if (action.type === ACTION_TYPES.SAFE) {
    audit.log({
      action: action.type,
      target: action.target,
      result: "allowed",
      reason: "safe-action",
    });
    return proxy.web(req, res);
  }

  // Log the attempt
  audit.log({
    action: action.type,
    target: action.target,
    result: "intercepted",
    reason: "sensitive-action",
    detail: action.summary,
  });

  console.log(
    `  [INTERCEPT] ${action.type}: ${action.target} — ${action.summary}`
  );

  // Check VE authorization
  let veResult;
  try {
    veResult = await checkAuthorization(
      CONFIG.veUrl,
      CONFIG.veApiKey,
      CONFIG.agentId
    );
  } catch (err) {
    // Fail-closed: VE unreachable = block
    console.log(`  [BLOCKED] VE unreachable: ${err.message}`);
    audit.log({
      action: action.type,
      target: action.target,
      result: "blocked",
      reason: "ve-unreachable",
      detail: err.message,
    });
    res.writeHead(503, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error:
          "CROCbox: Action blocked. Verification service unavailable. Fail-closed.",
        action: action.type,
        target: action.target,
      })
    );
    return;
  }

  // VE returned denied
  if (
    veResult.entity_status !== "active" ||
    !veResult.active_use_cards ||
    veResult.active_use_cards.length === 0
  ) {
    console.log(`  [BLOCKED] No active authorization for agent`);
    audit.log({
      action: action.type,
      target: action.target,
      result: "blocked",
      reason: "ve-denied",
      detail: `entity_status: ${veResult.entity_status}, active_cards: ${
        veResult.active_use_cards ? veResult.active_use_cards.length : 0
      }`,
    });
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error:
          "CROCbox: Action blocked. Agent does not have active authorization.",
        action: action.type,
        target: action.target,
        entity_status: veResult.entity_status,
      })
    );
    return;
  }

  // Check if this action type is covered by active permissions
  const actionAllowed = checkActionPermission(veResult, action);

  if (actionAllowed === "allowed") {
    // Permission exists and action is within scope — pass through
    console.log(`  [ALLOWED] ${action.type}: ${action.target}`);
    audit.log({
      action: action.type,
      target: action.target,
      result: "allowed",
      reason: "ve-authorized",
    });
    return proxy.web(req, res);
  }

  // Check session memory for "Allow & Remember"
  if (consent.hasSessionGrant(action.type, action.target)) {
    console.log(`  [ALLOWED] ${action.type}: ${action.target} (session grant)`);
    audit.log({
      action: action.type,
      target: action.target,
      result: "allowed",
      reason: "session-grant",
    });
    return proxy.web(req, res);
  }

  // Need real-time consent
  console.log(`  [CONSENT] Requesting consent for ${action.type}: ${action.target}`);

  // ── B.4 VE Gate: verify before consent ──
  let veDecisionMain = null;
  try {
    const sessionId = process.env.CROCBOX_SESSION_ID || "session-" + Date.now();
    veDecisionMain = await veClient.verify(action.type, null, sessionId);
    console.log(`  [VE] verify() returned: ${veDecisionMain.decision}${veDecisionMain.decision_id ? " (id: " + veDecisionMain.decision_id + ")" : ""}`);
  } catch (veErr) {
    console.log(`  [VE] verify() error (fail-closed): ${veErr.message}`);
    veDecisionMain = { decision: "denied", decision_id: null, reason: "ve-error", source: "ve_error" };
  }
  if (veDecisionMain.decision !== "approved") {
    audit.log({ action: action.type, target: action.target, result: "blocked", reason: "ve-denied", detail: veDecisionMain.reason || "VE did not approve", decision_id: veDecisionMain.decision_id || null });
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "CROCbox: Action blocked. Trust Network did not authorize.", action: action.type, target: action.target }));
    return;
  }
  // ── VE approved — proceed to local consent ──

  try {
    const decision = await consent.requestConsent(action);

    if (decision === "allow") {
      console.log(`  [ALLOWED] ${action.type}: ${action.target} (user consent)`);
      audit.log({
        action: action.type,
        target: action.target,
        result: "allowed",
        reason: "user-consent",
        decision_id: veDecisionMain ? veDecisionMain.decision_id : null,
      });
      return proxy.web(req, res);
    }

    if (decision === "remember") {
      consent.addSessionGrant(action.type, action.target);
      console.log(
        `  [ALLOWED] ${action.type}: ${action.target} (user consent + remember)`
      );
      audit.log({
        action: action.type,
        target: action.target,
        result: "allowed",
        reason: "user-consent-remember",
        decision_id: veDecisionMain ? veDecisionMain.decision_id : null,
      });
      return proxy.web(req, res);
    }

    // Denied or timed out
    console.log(
      `  [BLOCKED] ${action.type}: ${action.target} (user ${decision})`
    );
    audit.log({
      action: action.type,
      target: action.target,
      result: "blocked",
      reason: `user-${decision}`,
      decision_id: veDecisionMain ? veDecisionMain.decision_id : null,
    });
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: `CROCbox: Action blocked. User ${decision}.`,
        action: action.type,
        target: action.target,
      })
    );
  } catch (err) {
    // Consent system error = fail-closed
    console.log(`  [BLOCKED] Consent error: ${err.message}`);
    audit.log({
      action: action.type,
      target: action.target,
      result: "blocked",
      reason: "consent-error",
      detail: err.message,
      decision_id: veDecisionMain ? veDecisionMain.decision_id : null,
    });
    res.writeHead(503, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: "CROCbox: Action blocked. Consent system error. Fail-closed.",
      })
    );
  }
}

// ── Permission Checker ────────────────────────────────────────────
function checkActionPermission(veResult, action) {
  if (!veResult.active_use_cards) return "needs-consent";

  for (const card of veResult.active_use_cards) {
    if (!card.actions) continue;
    const actionMap = {
      [ACTION_TYPES.EMAIL]: "send_email",
      [ACTION_TYPES.API_CALL]: "api_call",
      [ACTION_TYPES.SHELL]: "shell_exec",
    };
    const mappedAction = actionMap[action.type];
    if (mappedAction && card.actions.includes(mappedAction)) {
      return "allowed";
    }
    // Also check for broad "read" or "derive" permissions
    if (card.actions.includes("Read") || card.actions.includes("Derive")) {
      if (action.type === ACTION_TYPES.API_CALL) {
        return "allowed";
      }
    }
  }

  return "needs-consent";
}

// ── HTTP Server ───────────────────────────────────────────────────
const server = http.createServer(handleRequest);

// WebSocket passthrough for OpenClaw's WS connections
server.on("upgrade", (req, socket, head) => {
  proxy.ws(req, socket, head);
});

// ── Start ─────────────────────────────────────────────────────────
function start() {
  validateConfig();

  server.listen(CONFIG.proxyPort, "127.0.0.1", () => {
    console.log("");
    console.log("  ╔══════════════════════════════════════╗");
    console.log("  ║   CROCbox CARD Proxy v0.1.0-alpha   ║");
    console.log("  ║   Consent · Authorization · Risk     ║");
    console.log("  ║   Documentation                      ║");
    console.log("  ╚══════════════════════════════════════╝");
    console.log("");
    console.log(`  Proxy listening:    http://127.0.0.1:${CONFIG.proxyPort}`);
    console.log(
      `  OpenClaw gateway:   http://${CONFIG.gatewayHost}:${CONFIG.gatewayPort}`
    );
    console.log(`  VE endpoint:        ${CONFIG.veUrl}`);
    console.log(`  Agent ID:           ${CONFIG.agentId}`);
    console.log(`  Consent timeout:    ${CONFIG.consentTimeoutMs / 1000}s`);
    console.log(`  Mode:               FAIL-CLOSED`);
    console.log("");
    console.log(
      `  Dashboard:          http://127.0.0.1:${CONFIG.dashboardPort}`
    );
    console.log("");

    // Start the consent dashboard WebSocket server
    consent.startWsServer(server);
  });
}

module.exports = { start, CONFIG };

// Run if called directly
if (require.main === module) {

  start();
}
