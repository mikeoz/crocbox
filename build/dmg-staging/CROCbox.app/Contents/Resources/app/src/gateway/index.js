/**
 * CROCbox OpenClaw Gateway — src/gateway/index.js
 *
 * Registers CROCbox as the HTTP proxy for OpenClaw.
 * All outbound traffic from OpenClaw routes through
 * the CARD Proxy on port 18790 for classify/consent/audit.
 *
 * Architecture:
 *   OpenClaw (outbound) → Gateway health check → CARD Proxy (:18790) → Internet
 *
 * Fail-closed: if CARD Proxy is not reachable at startup, we refuse to start.
 */

"use strict";
require("dotenv").config({ path: require("path").join(__dirname, "../../.env") });

const http  = require("http");
const https = require("https");

const PROXY_PORT    = parseInt(process.env.CROCBOX_PROXY_PORT  || "18790");
const GATEWAY_PORT  = parseInt(process.env.CROCBOX_GATEWAY_PORT || "18791");
const PROXY_HOST    = process.env.CROCBOX_PROXY_HOST || "127.0.0.1";

// ── Fail-closed startup check ────────────────────────────────────────────────
// If the CARD Proxy isn't already running, we refuse to start.
// This guarantees: no proxy = no gateway = agent cannot reach internet.

function checkProxyReachable() {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: PROXY_HOST, port: PROXY_PORT, path: "/crocbox/health", timeout: 3000 },
      (res) => {
        res.resume();
        if (res.statusCode === 200) {
          resolve();
        } else {
          // Proxy is up but returned unexpected status — still reachable, that's fine
          resolve();
        }
      }
    );
    req.on("error", () =>
      reject(new Error(
        `CARD Proxy not reachable at ${PROXY_HOST}:${PROXY_PORT}. ` +
        `Start the proxy first, then start the gateway.`
      ))
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`CARD Proxy health check timed out.`));
    });
  });
}

// ── Gateway HTTP server ──────────────────────────────────────────────────────
// This server does two things:
//   1. Responds to health checks so the launcher knows we're up
//   2. Acts as an HTTP CONNECT proxy — forwards all requests to CARD Proxy

function createGatewayServer() {
  const server = http.createServer((req, res) => {
    // Health check endpoint
    if (req.url === "/crocbox/gateway/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok",
        service: "crocbox-gateway",
        proxy: `${PROXY_HOST}:${PROXY_PORT}`,
        timestamp: new Date().toISOString(),
      }));
      return;
    }

    // All other requests: forward to CARD Proxy as-is
    // The proxy's classify.js will inspect the host/url and decide what to do
    forwardToProxy(req, res);
  });

  // Handle CONNECT tunnels (HTTPS) — forward to CARD Proxy
  server.on("connect", (req, clientSocket, head) => {
    forwardConnectToProxy(req, clientSocket, head);
  });

  return server;
}

// ── Forward plain HTTP requests to CARD Proxy ────────────────────────────────
function forwardToProxy(req, res) {
  const options = {
    host:    PROXY_HOST,
    port:    PROXY_PORT,
    path:    req.url,
    method:  req.method,
    headers: { ...req.headers, "X-CROCbox-Gateway": "18791" },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    console.error(`[Gateway] Forward error: ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        error: "CROCbox Gateway: CARD Proxy unreachable. Action blocked.",
      }));
    }
  });

  req.pipe(proxyReq);
}

// ── Forward HTTPS CONNECT tunnels to CARD Proxy ──────────────────────────────
// When OpenClaw makes an HTTPS call, it sends a CONNECT request first.
// We forward that tunnel request to the CARD Proxy so it can inspect it.
function forwardConnectToProxy(req, clientSocket, head) {
  const proxySocket = require("net").connect(PROXY_PORT, PROXY_HOST, () => {
    // Re-send the CONNECT request to the CARD Proxy
    proxySocket.write(
      `CONNECT ${req.url} HTTP/1.1\r\nHost: ${req.url}\r\n\r\n`
    );
    proxySocket.write(head);
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    proxySocket.pipe(clientSocket);
    clientSocket.pipe(proxySocket);
  });

  proxySocket.on("error", (err) => {
    console.error(`[Gateway] CONNECT tunnel error: ${err.message}`);
    clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
  });

  clientSocket.on("error", () => proxySocket.destroy());
}

// ── Startup ──────────────────────────────────────────────────────────────────
async function start() {
  console.log("");
  console.log("  ╔══════════════════════════════════════╗");
  console.log("  ║   CROCbox OpenClaw Gateway          ║");
  console.log("  ║   Routing agent traffic to CARD      ║");
  console.log("  ║   Proxy for consent + audit          ║");
  console.log("  ╚══════════════════════════════════════╝");
  console.log("");

  // Fail-closed: refuse to start if proxy isn't up
  try {
    await checkProxyReachable();
    console.log(`  [Gateway] CARD Proxy confirmed at ${PROXY_HOST}:${PROXY_PORT} ✓`);
  } catch (err) {
    console.error(`\n  [Gateway] FATAL — ${err.message}\n`);
    process.exit(1);
  }

  const server = createGatewayServer();

  server.listen(GATEWAY_PORT, "127.0.0.1", () => {
    console.log(`  [Gateway] Listening on port ${GATEWAY_PORT}`);
    console.log(`  [Gateway] Forwarding all traffic → CARD Proxy :${PROXY_PORT}`);
    console.log(`  [Gateway] Fail-closed: proxy down = agent blocked`);
    console.log("");
    console.log(`  Configure OpenClaw with:`);
    console.log(`    HTTP_PROXY=http://127.0.0.1:${GATEWAY_PORT}`);
    console.log(`    HTTPS_PROXY=http://127.0.0.1:${GATEWAY_PORT}`);
    console.log("");
  });

  // Graceful shutdown
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
  process.on("SIGINT",  () => server.close(() => process.exit(0)));
}

start();
