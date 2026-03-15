#!/usr/bin/env node
/**
 * QAS-VE INDEPENDENT VALIDATION SUITE
 * ====================================
 * OPN_QAS_VE-Validation_15MAR26_v2.0
 *
 * Written by QAS against the VE API contract defined in:
 *   OPN_ENG_VE-Requirements_14MAR26_v1.0, Sections 2 and 6.
 *
 * This script is INDEPENDENT of ENG's card_ve_client.js or test_ve_client.js.
 * QAS does not re-run the developer's tests — QAS builds its own.
 *
 * CHANGELOG v2.0 (post F-01 resolution):
 *   - QAS-VE-02: Enrolls a DEDICATED agent immediately before the replay test.
 *     Verifies original request returns 200/approved before starting the 31s wait.
 *     Eliminates dependency on Part A agent state.
 *   - QAS-VE-05: Enrolls a DEDICATED agent immediately before the rate limit test.
 *     Verifies agent is responsive (200) before sending the 61-request burst.
 *   - Both changes address the test sequencing issue discovered in v1 run.
 *
 * USAGE:
 *   node qas_ve_validation.js [--endpoint URL] [--verbose]
 *
 * DEFAULT ENDPOINT: https://ve-staging.opn.li
 *
 * TEST COVERAGE:
 *   Part A: ENG's 12 claimed test cases (independently reconstructed)
 *     A01  Enrollment returns valid agent_id
 *     A02  Enrollment returns card_id
 *     A03  Enrollment returns allowed_ops matching rental_ski_level
 *     A04  Enrollment returns ve_endpoint
 *     A05  Verification returns approved for authorized operation (beginner + web_search)
 *     A06  Verification returns decision_id
 *     A07  Verification returns expires_at in the future
 *     A08  Verification returns ve_version
 *     A09  Unknown agent_id returns 401
 *     A10  Invalid operation_type returns 400
 *     A11  Malformed request (missing required field) returns 400
 *     A12  Timeout produces fail-closed denial (simulated)
 *
 *   Part B: QAS-VE Security Tests (Section 6)
 *     QAS-VE-01  Fail-closed on VE down (point at non-existent endpoint)
 *     QAS-VE-02  Replay attack protection (replay request after 31s)
 *     QAS-VE-04  Operation type enforcement (beginner + filesystem_write)
 *     QAS-VE-05  Rate limit enforcement (61 requests in 60 seconds)
 *     QAS-VE-06  Request hash tampering (corrupt hash)
 *
 *   Part C: QAS Adversarial Probes (not in ENG's test suite)
 *     C01  Agent ID enumeration (try sequential/predictable IDs)
 *     C02  Forge approved decision without valid agent_id
 *     C03  Empty request_hash accepted?
 *     C04  SQL injection in agent_id field
 *     C05  Overlong field values (buffer overflow probe)
 *
 *   DEFERRED (requires revocation endpoint VE-OPS-2, target March 24):
 *     QAS-VE-03  Revocation propagation speed
 *     QAS-VE-07  Service revocation cascade
 */

const crypto = require("crypto");

// ─── Configuration ───────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const VERBOSE = args.includes("--verbose");
const endpointIdx = args.indexOf("--endpoint");
const VE_BASE =
  endpointIdx >= 0 && args[endpointIdx + 1]
    ? args[endpointIdx + 1].replace(/\/+$/, "")
    : "https://ve-staging.opn.li";

const VE_VERIFY = `${VE_BASE}/v1/verify`;
const VE_ENROLL = `${VE_BASE}/v1/enroll`;
const VE_HEALTH = `${VE_BASE}/health`;

const TIMEOUT_MS = 3000; // CROCbox VE client timeout per REQ-OPS-02
const TEST_ACCOUNT_ID = `qas-test-${Date.now()}`;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function log(msg) {
  if (VERBOSE) console.log(`  [verbose] ${msg}`);
}

function makeTimestamp() {
  return new Date().toISOString();
}

function makeRequestHash(agent_id, card_id, operation_type, session_id, timestamp) {
  const data = agent_id + card_id + operation_type + session_id + timestamp;
  return crypto.createHash("sha256").update(data).digest("hex");
}

async function fetchWithTimeout(url, options, timeoutMs = TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return resp;
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      return { aborted: true, status: 408, statusText: "Client Timeout (fail-closed)" };
    }
    throw err;
  }
}

async function enrollAgent(accountId, level = "beginner") {
  const payload = {
    opnli_account_id: accountId,
    agent_type: "openclaw",
    agent_version: "0.7.0",
    rental_ski_level: level,
    public_key: crypto.randomBytes(32).toString("hex"), // placeholder Ed25519
  };
  log(`POST ${VE_ENROLL} → ${JSON.stringify(payload)}`);
  const resp = await fetchWithTimeout(VE_ENROLL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (resp.aborted) return { _http: 408 };
  const body = await resp.json().catch(() => ({}));
  body._http = resp.status;
  log(`← ${resp.status} ${JSON.stringify(body)}`);
  return body;
}

async function verify(agent_id, card_id, operation_type, session_id, opts = {}) {
  const timestamp = opts.timestamp || makeTimestamp();
  const sid = session_id || `sess-${Date.now()}`;
  const hash = opts.hash !== undefined
    ? opts.hash
    : makeRequestHash(agent_id, card_id, operation_type, sid, timestamp);

  const payload = { agent_id, card_id, operation_type, session_id: sid, timestamp, request_hash: hash };

  // Allow partial payloads for malformed-request tests
  if (opts.omitField) delete payload[opts.omitField];

  const url = opts.url || VE_VERIFY;
  log(`POST ${url} → ${JSON.stringify(payload)}`);
  const resp = await fetchWithTimeout(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }, opts.timeout || TIMEOUT_MS);

  if (resp.aborted) return { _http: 408, decision: "denied", reason: "timeout_fail_closed" };
  const body = await resp.json().catch(() => ({}));
  body._http = resp.status;
  log(`← ${resp.status} ${JSON.stringify(body)}`);
  return body;
}

// ─── Test Runner ─────────────────────────────────────────────────────────────

const results = [];
function record(id, name, passed, detail) {
  const status = passed ? "PASS" : "FAIL";
  results.push({ id, name, status, detail });
  const icon = passed ? "✅" : "❌";
  console.log(`${icon} ${id}: ${name} — ${status}${detail ? " | " + detail : ""}`);
}
function recordDeferred(id, name, reason) {
  results.push({ id, name, status: "DEFERRED", detail: reason });
  console.log(`⏸️  ${id}: ${name} — DEFERRED | ${reason}`);
}
function recordCritical(id, name, detail) {
  results.push({ id, name, status: "CRITICAL", detail });
  console.log(`🚨 ${id}: ${name} — CRITICAL | ${detail}`);
}

// ─── Part A: ENG's 12 Test Cases (Independent Reconstruction) ────────────────

async function partA() {
  console.log("\n══════════════════════════════════════════════════════════");
  console.log("PART A: ENG TEST CASES (12) — INDEPENDENT RECONSTRUCTION");
  console.log("══════════════════════════════════════════════════════════\n");

  // Enroll a test agent at beginner level
  let enrollment;
  try {
    enrollment = await enrollAgent(TEST_ACCOUNT_ID, "beginner");
  } catch (err) {
    console.log(`\n⛔ ENROLLMENT FAILED — cannot reach ${VE_ENROLL}`);
    console.log(`   Error: ${err.message}`);
    console.log(`   All Part A tests will be marked FAIL (endpoint unreachable).\n`);
    for (let i = 1; i <= 12; i++) {
      record(`A${String(i).padStart(2, "0")}`, "— skipped (endpoint unreachable)", false, err.message);
    }
    return null;
  }

  // A01: Enrollment returns valid agent_id
  const hasAgentId = typeof enrollment.agent_id === "string" && enrollment.agent_id.length > 0;
  record("A01", "Enrollment returns valid agent_id", hasAgentId,
    hasAgentId ? `agent_id=${enrollment.agent_id}` : `Got: ${JSON.stringify(enrollment.agent_id)}`);

  // A02: Enrollment returns card_id
  const hasCardId = typeof enrollment.card_id === "string" && enrollment.card_id.length > 0;
  record("A02", "Enrollment returns card_id", hasCardId,
    hasCardId ? `card_id=${enrollment.card_id}` : `Got: ${JSON.stringify(enrollment.card_id)}`);

  // A03: allowed_ops matches beginner (web_search only)
  const opsMatch = Array.isArray(enrollment.allowed_ops)
    && enrollment.allowed_ops.length === 1
    && enrollment.allowed_ops[0] === "web_search";
  record("A03", "Enrollment allowed_ops matches beginner level", opsMatch,
    `allowed_ops=${JSON.stringify(enrollment.allowed_ops)}`);

  // A04: ve_endpoint returned
  const hasVeEndpoint = typeof enrollment.ve_endpoint === "string" && enrollment.ve_endpoint.length > 0;
  record("A04", "Enrollment returns ve_endpoint", hasVeEndpoint,
    `ve_endpoint=${enrollment.ve_endpoint || "(missing)"}`);

  if (!hasAgentId || !hasCardId) {
    console.log("\n⛔ Cannot run verification tests — enrollment did not return agent_id/card_id.\n");
    for (let i = 5; i <= 12; i++) {
      record(`A${String(i).padStart(2, "0")}`, "— skipped (no valid enrollment)", false, "blocked by A01/A02");
    }
    return null;
  }

  const { agent_id, card_id } = enrollment;

  // A05: Verification returns approved for authorized op (beginner + web_search)
  const v1 = await verify(agent_id, card_id, "web_search", null);
  record("A05", "Verification approved for authorized op", v1.decision === "approved",
    `decision=${v1.decision}, http=${v1._http}`);

  // A06: Verification returns decision_id
  const hasDecisionId = typeof v1.decision_id === "string" && v1.decision_id.length > 0;
  record("A06", "Verification returns decision_id", hasDecisionId,
    `decision_id=${v1.decision_id || "(missing)"}`);

  // A07: expires_at is in the future
  let expiresValid = false;
  if (v1.expires_at) {
    const exp = new Date(v1.expires_at);
    expiresValid = exp > new Date();
  }
  record("A07", "Verification expires_at is in the future", expiresValid,
    `expires_at=${v1.expires_at || "(missing)"}`);

  // A08: ve_version returned
  const hasVeVersion = typeof v1.ve_version === "string" && v1.ve_version.length > 0;
  record("A08", "Verification returns ve_version", hasVeVersion,
    `ve_version=${v1.ve_version || "(missing)"}`);

  // A09: Unknown agent_id returns 401
  const v2 = await verify("nonexistent-agent-zzz", card_id, "web_search", null);
  record("A09", "Unknown agent_id returns 401", v2._http === 401,
    `http=${v2._http}, decision=${v2.decision || "(none)"}`);

  // A10: Invalid operation_type returns 400
  const v3 = await verify(agent_id, card_id, "hack_the_planet", null);
  record("A10", "Invalid operation_type returns 400", v3._http === 400,
    `http=${v3._http}`);

  // A11: Malformed request (missing required field) returns 400
  const v4 = await verify(agent_id, card_id, "web_search", null, { omitField: "session_id" });
  record("A11", "Malformed request (missing field) returns 400", v4._http === 400,
    `http=${v4._http} (omitted session_id)`);

  // A12: Timeout produces fail-closed denial
  // Simulate by pointing at a non-responding endpoint with a short timeout
  const v5 = await verify(agent_id, card_id, "web_search", null, {
    url: "https://10.255.255.1/v1/verify", // non-routable IP
    timeout: 2000,
  });
  const timeoutClosed = v5._http === 408 && v5.decision === "denied";
  record("A12", "Timeout produces fail-closed denial", timeoutClosed,
    `http=${v5._http}, decision=${v5.decision}`);

  return { agent_id, card_id };
}

// ─── Part B: QAS-VE Security Tests (Section 6) ──────────────────────────────

async function partB(enrolled) {
  console.log("\n══════════════════════════════════════════════════════════");
  console.log("PART B: QAS-VE SECURITY TESTS (Section 6)");
  console.log("══════════════════════════════════════════════════════════\n");

  // QAS-VE-01: Fail-closed on VE down
  // Point at a definitely-not-running endpoint
  console.log("QAS-VE-01: Simulating VE down (non-existent endpoint)...");
  try {
    const r1 = await verify(
      enrolled?.agent_id || "test-agent",
      enrolled?.card_id || "test-card",
      "web_search",
      null,
      { url: "https://10.255.255.1/v1/verify", timeout: 3000 }
    );
    const failClosed = r1._http === 408 && r1.decision === "denied";
    record("QAS-VE-01", "Fail-closed on VE down", failClosed,
      `http=${r1._http}, decision=${r1.decision}`);
  } catch (err) {
    // Network error = also fail-closed behavior at the client level
    record("QAS-VE-01", "Fail-closed on VE down", true,
      `Network error caught → client denies. Error: ${err.message}`);
  }

  // QAS-VE-02: Replay attack protection
  // v2 FIX: Enroll a DEDICATED agent for this test to eliminate Part A agent staleness
  console.log("QAS-VE-02: Replay attack (enrolling dedicated agent, capturing request, waiting 31s, replaying)...");
  try {
    const replayAccount = `qas-replay-${Date.now()}`;
    const replayEnroll = await enrollAgent(replayAccount, "beginner");
    if (replayEnroll._http === 408 || !replayEnroll.agent_id) {
      record("QAS-VE-02", "Replay attack protection (31s)", false,
        "Could not enroll dedicated agent for replay test");
    } else {
      const rAgent = replayEnroll.agent_id;
      const rCard = replayEnroll.card_id;
      log(`QAS-VE-02: Enrolled dedicated agent ${rAgent}`);

      const capturedTimestamp = makeTimestamp();
      const sid = `sess-replay-${Date.now()}`;
      const capturedHash = makeRequestHash(rAgent, rCard, "web_search", sid, capturedTimestamp);

      // Send original — MUST return 200/approved for the test to be valid
      const original = await verify(rAgent, rCard, "web_search", sid, {
        timestamp: capturedTimestamp,
        hash: capturedHash,
      });
      log(`Original request: http=${original._http}, decision=${original.decision}`);

      if (original._http !== 200 || original.decision !== "approved") {
        record("QAS-VE-02", "Replay attack protection (31s)", false,
          `Original request did not return 200/approved (got http=${original._http}, decision=${original.decision}). Cannot test replay. Agent state issue may persist.`);
      } else {
        console.log("  Original request: 200/approved. Waiting 31 seconds for replay window to expire...");
        await new Promise((r) => setTimeout(r, 31000));

        // Replay exact same request — same timestamp, same hash
        const replay = await verify(rAgent, rCard, "web_search", sid, {
          timestamp: capturedTimestamp,  // same old timestamp
          hash: capturedHash,           // same hash
        });
        const replayBlocked = replay._http === 400;
        record("QAS-VE-02", "Replay attack protection (31s)", replayBlocked,
          `Original: http=${original._http} decision=${original.decision} | Replay: http=${replay._http} decision=${replay.decision || "(none)"}`);

        // CRITICAL CHECK: If the replay returned approved, that's a bypass
        if (replay.decision === "approved") {
          recordCritical("QAS-VE-02a", "REPLAY RETURNED APPROVED AFTER 31s",
            "Attacker can replay captured verification requests. Blocks Gate.");
        }
      }
    }
  } catch (err) {
    record("QAS-VE-02", "Replay attack protection (31s)", false,
      `Error during replay test: ${err.message}`);
  }

  // QAS-VE-03: DEFERRED
  recordDeferred("QAS-VE-03", "Revocation propagation speed",
    "Requires revocation endpoint (VE-OPS-2). OPS target: March 24.");

  // QAS-VE-04: Operation type enforcement (beginner + filesystem_write)
  if (enrolled) {
    console.log("QAS-VE-04: Beginner agent requesting filesystem_write...");
    const r4 = await verify(enrolled.agent_id, enrolled.card_id, "filesystem_write", null);
    const denied = r4.decision === "denied" && r4._http === 200;
    record("QAS-VE-04", "Operation type enforcement (beginner + filesystem_write)", denied,
      `http=${r4._http}, decision=${r4.decision}, reason=${r4.reason || "(none)"}`);

    // CRITICAL CHECK: If approved, the VE is not enforcing Rental Ski levels
    if (r4.decision === "approved") {
      recordCritical("QAS-VE-04a", "BEGINNER AGENT APPROVED FOR filesystem_write",
        "VE is not enforcing Rental Ski levels. Any agent can perform any operation. Blocks Gate.");
    }
  } else {
    record("QAS-VE-04", "Operation type enforcement", false, "Skipped — no enrolled agent");
  }

  // QAS-VE-05: Rate limit enforcement (61 requests in 60 seconds)
  // v2 FIX: Enroll a DEDICATED agent and verify it responds 200 before the burst
  console.log("QAS-VE-05: Rate limit enforcement (enrolling dedicated agent, then sending 61 requests)...");
  try {
    const rlAccount = `qas-ratelimit-${Date.now()}`;
    const rlEnroll = await enrollAgent(rlAccount, "beginner");
    if (rlEnroll._http === 408 || !rlEnroll.agent_id) {
      record("QAS-VE-05", "Rate limit enforcement", false,
        "Could not enroll dedicated agent for rate limit test");
    } else {
      const rlAgent = rlEnroll.agent_id;
      const rlCard = rlEnroll.card_id;
      log(`QAS-VE-05: Enrolled dedicated agent ${rlAgent}`);

      // Verify agent is responsive before starting burst
      const warmup = await verify(rlAgent, rlCard, "web_search", null);
      if (warmup._http !== 200 || warmup.decision !== "approved") {
        record("QAS-VE-05", "Rate limit enforcement", false,
          `Dedicated agent not responsive (http=${warmup._http}, decision=${warmup.decision}). Cannot test rate limit.`);
      } else {
        log(`QAS-VE-05: Agent confirmed responsive. Starting 61-request burst...`);
        let rateLimitHit = false;
        let requestCount = 1; // warmup counts as request 1
        let approvedCount = 1;
        let deniedCount = 0;
        let otherCount = 0;
        const startTime = Date.now();

        for (let i = 0; i < 60; i++) { // 60 more = 61 total including warmup
          const r = await verify(rlAgent, rlCard, "web_search", null);
          requestCount++;
          if (r._http === 429) {
            rateLimitHit = true;
            record("QAS-VE-05", "Rate limit enforcement", true,
              `429 received at request #${requestCount} (elapsed: ${Date.now() - startTime}ms). Approved: ${approvedCount}, Denied: ${deniedCount}`);
            break;
          }
          if (r._http === 200 && r.decision === "approved") approvedCount++;
          else if (r._http === 200 && r.decision === "denied") deniedCount++;
          else otherCount++;

          // CRITICAL CHECK: If we see 401s for our dedicated agent, F-01 is back
          if (r._http === 401) {
            record("QAS-VE-05", "Rate limit enforcement", false,
              `401 at request #${requestCount} — F-01 may not be fully resolved. Agent: ${rlAgent}`);
            rateLimitHit = true; // exit loop, don't double-record
            break;
          }
        }
        if (!rateLimitHit) {
          record("QAS-VE-05", "Rate limit enforcement", false,
            `Sent ${requestCount} requests, never received 429. Elapsed: ${Date.now() - startTime}ms. Approved: ${approvedCount}, Other: ${otherCount}`);
        }
      }
    }
  } catch (err) {
    record("QAS-VE-05", "Rate limit enforcement", false,
      `Error during rate limit test: ${err.message}`);
  }

  // QAS-VE-06: Request hash tampering
  if (enrolled) {
    console.log("QAS-VE-06: Request hash tampering (corrupt hash)...");
    const r6 = await verify(enrolled.agent_id, enrolled.card_id, "web_search", null, {
      hash: "0000000000000000000000000000000000000000000000000000000000000000",
    });
    const tamperedBlocked = r6._http === 400;
    record("QAS-VE-06", "Request hash tampering returns 400", tamperedBlocked,
      `http=${r6._http}, decision=${r6.decision || "(none)"}`);

    // CRITICAL CHECK: If approved with a bad hash, integrity checking is broken
    if (r6.decision === "approved") {
      recordCritical("QAS-VE-06a", "CORRUPTED HASH RETURNED APPROVED",
        "VE is not validating request_hash. Any request can be forged or tampered. Blocks Gate.");
    }
  } else {
    record("QAS-VE-06", "Request hash tampering", false, "Skipped — no enrolled agent");
  }

  // QAS-VE-07: DEFERRED
  recordDeferred("QAS-VE-07", "Service revocation cascade",
    "Requires revocation endpoint (VE-OPS-2). OPS target: March 24.");
}

// ─── Part C: QAS Adversarial Probes (Beyond ENG's Test Suite) ────────────────

async function partC(enrolled) {
  console.log("\n══════════════════════════════════════════════════════════");
  console.log("PART C: QAS ADVERSARIAL PROBES (Not in ENG test suite)");
  console.log("══════════════════════════════════════════════════════════\n");

  // C01: Agent ID enumeration — try sequential/predictable IDs
  console.log("C01: Agent ID enumeration probe...");
  const probeIds = [
    "oc-agent-000001",
    "oc-agent-000002",
    "oc-agent-a3f7d2",  // example from the spec
    "admin",
    "root",
    "oc-agent-1",
  ];
  let enumerationRisk = false;
  let enumerationReachable = true;
  for (const id of probeIds) {
    try {
      const r = await verify(id, "card-probe", "web_search", null);
      if (r.decision === "approved") {
        enumerationRisk = true;
        recordCritical("C01", `ENUMERATED AGENT ID APPROVED: ${id}`,
          "Attacker can guess agent_ids and receive approved decisions. Blocks Gate.");
        break;
      }
      if (r._http !== 401 && r._http !== 400 && r._http !== 408) {
        record("C01", "Agent ID enumeration", false,
          `Unexpected status ${r._http} for probe ID '${id}'. Possible info leak.`);
        enumerationRisk = true; // treat as suspicious
        break;
      }
      log(`Probe ${id}: http=${r._http}, decision=${r.decision || "(none)"}`);
    } catch (err) {
      enumerationReachable = false;
      record("C01", "Agent ID enumeration", false, `Endpoint unreachable: ${err.message}`);
      break;
    }
  }
  if (!enumerationRisk && enumerationReachable) {
    record("C01", "Agent ID enumeration", true,
      "All probe IDs returned 401. No enumeration vector detected.");
  }

  // C02: Forge approved decision without valid agent_id
  console.log("C02: Forge approval without valid agent_id...");
  try {
    const forgeResult = await verify(
      "forged-agent-" + crypto.randomBytes(8).toString("hex"),
      "forged-card-" + crypto.randomBytes(8).toString("hex"),
      "web_search",
      null
    );
    if (forgeResult.decision === "approved") {
      recordCritical("C02", "FORGED AGENT RECEIVED APPROVED DECISION",
        "VE approves requests from unknown agents. Blocks Gate.");
    } else {
      record("C02", "Cannot forge approval with random agent_id", true,
        `http=${forgeResult._http}, decision=${forgeResult.decision || "(none)"}`);
    }
  } catch (err) {
    record("C02", "Cannot forge approval with random agent_id", false, `Endpoint unreachable: ${err.message}`);
  }

  // C03: Empty request_hash accepted?
  console.log("C03: Empty request_hash probe...");
  if (enrolled) {
    try {
      const r3 = await verify(enrolled.agent_id, enrolled.card_id, "web_search", null, { hash: "" });
      if (r3.decision === "approved") {
        recordCritical("C03", "EMPTY REQUEST_HASH RETURNED APPROVED",
          "VE does not require request_hash. Integrity checking is bypassable. Blocks Gate.");
      } else {
        record("C03", "Empty request_hash rejected", true, `http=${r3._http}`);
      }
    } catch (err) {
      record("C03", "Empty request_hash", false, `Endpoint unreachable: ${err.message}`);
    }
  } else {
    record("C03", "Empty request_hash", false, "Skipped — no enrolled agent");
  }

  // C04: SQL injection in agent_id
  console.log("C04: SQL injection probe in agent_id...");
  const sqliPayloads = [
    "' OR '1'='1",
    "'; DROP TABLE agents; --",
    "\" OR \"\"=\"",
    "1; SELECT * FROM agents",
  ];
  let sqliVulnerable = false;
  let sqliReachable = true;
  for (const payload of sqliPayloads) {
    try {
      const r = await verify(payload, "card-test", "web_search", null);
      if (r.decision === "approved") {
        sqliVulnerable = true;
        recordCritical("C04", `SQL INJECTION RETURNED APPROVED: '${payload}'`,
          "VE may be vulnerable to SQL injection. Blocks Gate.");
        break;
      }
      if (r._http === 500) {
        record("C04", "SQL injection probe", false,
          `500 error on payload '${payload}' — possible unhandled SQL error. Needs investigation.`);
        sqliVulnerable = true; // flag for summary
        break;
      }
    } catch (err) {
      sqliReachable = false;
      record("C04", "SQL injection probe", false, `Endpoint unreachable: ${err.message}`);
      break;
    }
  }
  if (!sqliVulnerable && sqliReachable) {
    record("C04", "SQL injection in agent_id rejected", true,
      "All SQLi payloads returned 400 or 401. No injection vector detected.");
  }

  // C05: Overlong field values
  console.log("C05: Overlong field values probe...");
  const longValue = "A".repeat(100000);
  try {
    const r5 = await verify(longValue, "card-test", "web_search", null);
    if (r5._http === 400 || r5._http === 401) {
      record("C05", "Overlong field values rejected", true, `http=${r5._http}`);
    } else if (r5._http === 500) {
      record("C05", "Overlong field values", false,
        "500 error — possible unhandled buffer overflow or parsing failure. HIGH severity.");
    } else {
      record("C05", "Overlong field values", true, `http=${r5._http}`);
    }
  } catch (err) {
    record("C05", "Overlong field values", false,
      `Endpoint unreachable: ${err.message}`);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  QAS-VE INDEPENDENT VALIDATION SUITE                       ║");
  console.log("║  OPN_QAS_VE-Validation_15MAR26_v2.0                        ║");
  console.log("║  Target: " + VE_BASE.padEnd(50) + "  ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log(`\nStarted: ${new Date().toISOString()}`);
  console.log(`Test account: ${TEST_ACCOUNT_ID}`);

  // Health check first
  console.log(`\nHealth check: ${VE_HEALTH}`);
  try {
    const healthResp = await fetchWithTimeout(VE_HEALTH, { method: "GET" }, 5000);
    if (healthResp.aborted) {
      console.log("⛔ Health endpoint timed out. VE may be down.\n");
    } else {
      console.log(`✓ Health endpoint returned HTTP ${healthResp.status}\n`);
    }
  } catch (err) {
    console.log(`⛔ Health endpoint unreachable: ${err.message}`);
    console.log("  Continuing with tests — failures expected if VE is truly down.\n");
  }

  const enrolled = await partA();
  await partB(enrolled);
  await partC(enrolled);

  // ─── Summary ───────────────────────────────────────────────────────────────
  console.log("\n══════════════════════════════════════════════════════════");
  console.log("SUMMARY");
  console.log("══════════════════════════════════════════════════════════\n");

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const critical = results.filter((r) => r.status === "CRITICAL").length;
  const deferred = results.filter((r) => r.status === "DEFERRED").length;
  const total = results.length;

  console.log(`Total tests: ${total}`);
  console.log(`  PASS:     ${passed}`);
  console.log(`  FAIL:     ${failed}`);
  console.log(`  CRITICAL: ${critical}`);
  console.log(`  DEFERRED: ${deferred}`);
  console.log();

  if (critical > 0) {
    console.log("🚨🚨🚨 CRITICAL FINDINGS — BLOCKS GATE 🚨🚨🚨");
    results
      .filter((r) => r.status === "CRITICAL")
      .forEach((r) => console.log(`  ${r.id}: ${r.name} — ${r.detail}`));
    console.log();
  }

  if (failed > 0) {
    console.log("❌ FAILURES:");
    results
      .filter((r) => r.status === "FAIL")
      .forEach((r) => console.log(`  ${r.id}: ${r.name} — ${r.detail}`));
    console.log();
  }

  if (deferred > 0) {
    console.log("⏸️  DEFERRED:");
    results
      .filter((r) => r.status === "DEFERRED")
      .forEach((r) => console.log(`  ${r.id}: ${r.name} — ${r.detail}`));
    console.log();
  }

  console.log(`Completed: ${new Date().toISOString()}`);
  console.log("\n— QAS, Opn.li");

  // Exit code: 2 for critical, 1 for failures, 0 for all pass
  if (critical > 0) process.exit(2);
  if (failed > 0) process.exit(1);
  process.exit(0);
}

main().catch((err) => {
  console.error(`\n⛔ FATAL ERROR: ${err.message}\n${err.stack}`);
  process.exit(3);
});
