/**
 * CROCbox Action Classifier
 *
 * Examines an HTTP request and classifies it as one of:
 *   - EMAIL: outbound email send (SMTP, Gmail API, SendGrid, etc.)
 *   - API_CALL: outbound API call to external service
 *   - SHELL: shell command execution
 *   - SAFE: internal/LLM traffic that can pass through
 */

const ACTION_TYPES = {
  EMAIL: "email",
  API_CALL: "api_call",
  SHELL: "shell_exec",
  SAFE: "safe",
};

// Patterns that indicate email-sending actions
const EMAIL_PATTERNS = [
  /gmail.*send/i,
  /sendgrid/i,
  /mailgun/i,
  /smtp/i,
  /\/messages\/send/i,
  /\/mail\/send/i,
  /postmark/i,
  /ses.*sendemail/i,
  /\/v1\/email/i,
];

// Patterns that indicate shell execution
const SHELL_PATTERNS = [
  /\/exec/i,
  /\/spawn/i,
  /\/shell/i,
  /child_process/i,
  /system\.run/i,
  /tools\/exec/i,
  /command.*execute/i,
];

// Hosts that are considered safe (LLM backends, OpenClaw internals)
const SAFE_HOSTS = [
  "api.anthropic.com",
  "api.openai.com",
  "127.0.0.1",
  "localhost",
  "0.0.0.0",
];

/**
 * Classify an incoming HTTP request.
 *
 * @param {http.IncomingMessage} req
 * @returns {{ type: string, target: string, summary: string }}
 */
function classifyAction(req) {
  const url = req.url || "";
  const method = req.method || "GET";
  const host = req.headers.host || "";
  const contentType = req.headers["content-type"] || "";

  // Internal OpenClaw dashboard/UI requests are safe
  if (url.startsWith("/api/") && isSafeHost(host)) {
    return {
      type: ACTION_TYPES.SAFE,
      target: host + url,
      summary: "Internal OpenClaw request",
    };
  }

  // WebSocket upgrade requests for OpenClaw are safe
  if (req.headers.upgrade === "websocket") {
    return {
      type: ACTION_TYPES.SAFE,
      target: host,
      summary: "WebSocket connection (OpenClaw internal)",
    };
  }

  // Static file requests are safe
  if (url.match(/\.(js|css|html|png|jpg|svg|ico|woff|woff2|ttf)$/)) {
    return {
      type: ACTION_TYPES.SAFE,
      target: url,
      summary: "Static file request",
    };
  }

  // Check for email patterns
  for (const pattern of EMAIL_PATTERNS) {
    if (pattern.test(url) || pattern.test(host)) {
      return {
        type: ACTION_TYPES.EMAIL,
        target: extractEmailTarget(req),
        summary: `Email send via ${host || url}`,
      };
    }
  }

  // Check for shell execution patterns
  for (const pattern of SHELL_PATTERNS) {
    if (pattern.test(url)) {
      return {
        type: ACTION_TYPES.SHELL,
        target: url,
        summary: `Shell execution: ${url}`,
      };
    }
  }

  // Check body for tool calls (OpenClaw sends tool invocations as JSON)
  if (method === "POST" && contentType.includes("application/json")) {
    // We'll need to buffer the body to inspect it
    // For now, classify POST to external hosts as API calls
    if (!isSafeHost(host)) {
      return {
        type: ACTION_TYPES.API_CALL,
        target: host + url,
        summary: `API call to ${host}`,
      };
    }
  }

  // Check for outbound requests to unknown external services
  if (host && !isSafeHost(host)) {
    return {
      type: ACTION_TYPES.API_CALL,
      target: host + url,
      summary: `Outbound request to ${host}`,
    };
  }

  // Default: safe
  return {
    type: ACTION_TYPES.SAFE,
    target: url,
    summary: "Allowed traffic",
  };
}

function isSafeHost(host) {
  const hostname = host.split(":")[0];
  return SAFE_HOSTS.some(
    (safe) => hostname === safe || hostname.endsWith("." + safe)
  );
}

function extractEmailTarget(req) {
  // Best-effort extraction of email recipient from URL or headers
  const url = req.url || "";
  const match = url.match(/to=([^&]+)/);
  if (match) return decodeURIComponent(match[1]);
  return req.headers.host || "unknown";
}

module.exports = { classifyAction, ACTION_TYPES };
