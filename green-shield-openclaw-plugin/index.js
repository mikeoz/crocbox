// CROCbox Green Shield: OpenClaw plugin. Replaces the beta.15 dist patch.
// Every tool call must receive NHB consent before it runs, via the CROCbox
// Green Shield gate at 127.0.0.1:18793/green-shield-consent (green-shield-gate.js).
// Fail-closed: denial, gate unreachable, timeout, unreadable reply, or any
// error blocks the tool.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import http from "node:http";
import crypto from "node:crypto";

const GATE_HOST = "127.0.0.1";
const GATE_PORT = 18793;
const GATE_PATH = "/green-shield-consent";
const GATE_HTTP_TIMEOUT_MS = 70000; // longer than the gate's 65 s consent window
const HOOK_TIMEOUT_MS = 90000;      // longer than the HTTP timeout; OpenClaw's default is 15000
// Tool-search stand-ins. The real tool reaches this hook separately, right after.
const SKIP_TOOLS = new Set(["tool_search", "tool_describe", "tool_call"]);

function log(msg) { console.error("[green-shield] " + msg); }

function trimParams(params) {
  if (typeof params !== "object" || params === null) return {};
  return Object.fromEntries(
    Object.entries(params).slice(0, 10).map(([k, v]) => [k, typeof v === "string" ? v.substring(0, 200) : v])
  );
}

function askGate(toolName, params) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ toolName, params: trimParams(params), requestId: crypto.randomUUID() });
    const req = http.request({
      hostname: GATE_HOST, port: GATE_PORT, path: GATE_PATH, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      timeout: GATE_HTTP_TIMEOUT_MS,
    }, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => {
        try { resolve(JSON.parse(data)); } catch { resolve({ allowed: false, reason: "parse-error" }); }
      });
    });
    req.on("error", () => resolve({ allowed: false, reason: "consent-server-unreachable" }));
    req.on("timeout", () => { req.destroy(); resolve({ allowed: false, reason: "consent-timeout" }); });
    req.write(body);
    req.end();
  });
}

function block(reason) {
  return { block: true, blockReason: "CROCbox Green Shield: " + reason };
}

export default definePluginEntry({
  id: "crocbox-green-shield",
  name: "CROCbox Green Shield",
  description: "Asks the NHB for consent before every tool call (Human Consent Layer). Fail-closed.",
  register(api) {
    log("registered (hook timeoutMs=" + HOOK_TIMEOUT_MS + ")");
    api.on("before_tool_call", async (event) => {
      try {
        const toolName = String((event && event.toolName) || "tool");
        if (SKIP_TOOLS.has(toolName)) { log("skip stand-in " + toolName); return undefined; }
        const r = await askGate(toolName, event && event.params);
        if (r && r.allowed === true) { log("allowed " + toolName); return undefined; }
        const reason = (r && r.reason) || "consent-denied";
        log("blocked " + toolName + " (" + reason + ")");
        return block(reason + ". The user blocked this action. Do not retry. Respect the user's decision.");
      } catch (err) {
        log("error, blocking: " + String((err && err.message) || err));
        return block("consent gate error (" + String((err && err.message) || err) + "). Tool blocked for safety.");
      }
    }, { priority: 50, timeoutMs: HOOK_TIMEOUT_MS });
  },
});
