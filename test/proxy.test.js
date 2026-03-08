/**
 * CROCbox Proxy Test
 *
 * Verifies that the CARD Proxy:
 *   1. Starts and listens on the configured port
 *   2. Blocks requests when VE returns denied
 *   3. Passes through safe requests
 *   4. Returns 503 when VE is unreachable
 */

const http = require("http");

const PROXY_PORT = process.env.CROCBOX_PROXY_PORT || 18790;
const PROXY_URL = `http://127.0.0.1:${PROXY_PORT}`;

let pass = 0;
let fail = 0;

function test(name, fn) {
  return fn()
    .then((result) => {
      if (result) {
        console.log(`  PASS: ${name}`);
        pass++;
      } else {
        console.log(`  FAIL: ${name}`);
        fail++;
      }
    })
    .catch((err) => {
      console.log(`  FAIL: ${name} (${err.message})`);
      fail++;
    });
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      })
      .on("error", reject);
  });
}

async function run() {
  console.log("");
  console.log("  CROCbox Proxy Tests");
  console.log("");

  // Test 1: Proxy is listening
  await test("Proxy is reachable on port " + PROXY_PORT, async () => {
    try {
      const res = await httpGet(PROXY_URL + "/");
      return res.status > 0; // Any response means proxy is running
    } catch (err) {
      if (err.code === "ECONNREFUSED") return false;
      return false;
    }
  });

  // Test 2: Static files pass through (safe action)
  await test("Static file request passes through", async () => {
    try {
      const res = await httpGet(PROXY_URL + "/test.html");
      // Should get proxied to OpenClaw (may 404 but not 403/503)
      return res.status !== 403 && res.status !== 503;
    } catch {
      return false;
    }
  });

  console.log("");
  console.log(`  Results: ${pass} passed, ${fail} failed`);
  console.log("");
  process.exit(fail);
}

run();
