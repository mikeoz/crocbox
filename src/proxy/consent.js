/**
 * CROCbox CARD Proxy — Consent Manager (WebSocket)
 *
 * Manages the WebSocket endpoint at /crocbox/consent that the
 * Consent Dashboard connects to.
 */

const { WebSocketServer } = require("ws");
const crypto = require("crypto");

class ConsentManager {
  constructor(timeoutMs) {
    this.timeoutMs = timeoutMs || 300000;
    this.dashboardSocket = null;
    this.pendingConsents = new Map();
    this.sessionGrants = new Map();
    this.wss = null;
  }

  startWsServer(server) {
    this.wss = new WebSocketServer({ noServer: true });
    const existingListeners = server.listeners("upgrade");
    server.removeAllListeners("upgrade");

    server.on("upgrade", (req, socket, head) => {
      if (req.url === "/crocbox/consent") {
        this.wss.handleUpgrade(req, socket, head, (ws) => {
          this.wss.emit("connection", ws, req);
        });
      } else {
        for (const listener of existingListeners) {
          listener.call(server, req, socket, head);
        }
      }
    });

    this.wss.on("connection", (ws) => {
      console.log("  [CONSENT] Dashboard connected");
      if (this.dashboardSocket && this.dashboardSocket.readyState === 1) {
        console.log("  [CONSENT] Replacing previous dashboard connection (not force-closing)");
        this.dashboardSocket.removeAllListeners();
      }
      this.dashboardSocket = ws;

      ws.on("message", (raw) => {
        let msg;
        try { msg = JSON.parse(raw.toString()); }
        catch (e) { return; }
        this._handleDashboardMessage(msg);
      });

      ws.on("close", () => {
        console.log("  [CONSENT] Dashboard disconnected");
        if (this.dashboardSocket === ws) this.dashboardSocket = null;
        for (const [requestId, pending] of this.pendingConsents) {
          clearTimeout(pending.timer);
          pending.resolve("no-dashboard");
          this.pendingConsents.delete(requestId);
        }
      });

      ws.on("error", (err) => {
        console.error("  [CONSENT] Dashboard WS error:", err.message);
      });

      const pingInterval = setInterval(() => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "ping" }));
        else clearInterval(pingInterval);
      }, 30000);
      ws.on("close", () => clearInterval(pingInterval));
    });
  }

  _handleDashboardMessage(msg) {
    if (msg.type === "dashboard_connect") {
      console.log("  [CONSENT] Dashboard announced at", msg.timestamp || "unknown");
    } else if (msg.type === "consent_response") {
      this._resolveConsent(msg.request_id, msg.decision);
    }
  }

  _resolveConsent(requestId, decision) {
    const pending = this.pendingConsents.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pendingConsents.delete(requestId);

    let result;
    if (decision === "allow") result = "allow";
    else if (decision === "allow_remember") result = "remember";
    else result = "deny";

    console.log("  [CONSENT] User decision for " + requestId + ": " + result);
    pending.resolve(result);
  }

  requestConsent(action) {
    if (!this.dashboardSocket || this.dashboardSocket.readyState !== 1) {
      console.log("  [CONSENT] No dashboard connected. Blocking action (fail-closed).");
      return Promise.resolve("no-dashboard");
    }

    const requestId = "cr-" + crypto.randomBytes(8).toString("hex");
    const consentMsg = {
      type: "consent_request",
      request_id: requestId,
      action: action.type,
      target: action.target,
      detail: action.summary || "",
      timeout_s: this.timeoutMs / 1000,
      timestamp: new Date().toISOString(),
    };

    try {
      this.dashboardSocket.send(JSON.stringify(consentMsg));
    } catch (e) {
      return Promise.resolve("no-dashboard");
    }

    console.log("  [CONSENT] Sent consent request " + requestId + " to dashboard");

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingConsents.delete(requestId);
        console.log("  [CONSENT] Timeout for " + requestId + ". Blocking (fail-closed).");
        if (this.dashboardSocket && this.dashboardSocket.readyState === 1) {
          this.dashboardSocket.send(JSON.stringify({
            type: "consent_resolved",
            request_id: requestId,
            result: "timeout",
            reason: "Consent timed out",
          }));
        }
        resolve("timeout");
      }, this.timeoutMs);

      this.pendingConsents.set(requestId, {
        resolve, timer,
        action: action.type,
        target: action.target,
      });
    });
  }

  hasSessionGrant(actionType, target) {
    return this.sessionGrants.has(actionType + ":" + target);
  }

  addSessionGrant(actionType, target) {
    const key = actionType + ":" + target;
    this.sessionGrants.set(key, true);
    console.log("  [CONSENT] Session grant created:", key);
  }
}

module.exports = { ConsentManager };
