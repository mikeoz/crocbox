/**
 * @opnli/atl-devkit — Consent Gate
 * 
 * The core of the Agent Trust Layer. Inspects a stream of messages
 * between an AI agent and its execution environment. When the agent
 * acts on the world, the gate HOLDS the result and asks the human.
 * 
 * Two shield levels:
 * 
 *   GREEN SHIELD (Consent Before Execution):
 *     The gate intercepts a pre-execution approval request. The action
 *     has NOT happened yet. The human decides whether it happens.
 *     Requires the agent platform to broadcast approval events.
 * 
 *   YELLOW SHIELD (Consent Before Delivery):
 *     The gate detects that an action executed via a sequence gap in
 *     the agent event stream. The action HAS happened, but the result
 *     has not been delivered. The human decides whether to receive it.
 *     Works on ANY platform that streams sequential agent events.
 * 
 * The gate is fail-closed: if the human doesn't respond within the
 * timeout, the answer is NO. If the connection drops, the answer is
 * NO. There is no bypass.
 * 
 * Three-line integration:
 * 
 *   const { createConsentGate } = require('@opnli/atl-devkit');
 *   const gate = createConsentGate({ onConsent: showMyUI, timeout: 60000 });
 *   myProxy.onMessage(gate.inspect);
 * 
 * @see OPN_ENG_CROC-E2E-Invariants_13MAR26_v2, INV-5, INV-7
 */
'use strict';

const crypto = require('crypto');

/**
 * Create a consent gate for an agent message stream.
 * 
 * @param {object} options
 * @param {function} options.onConsent — Called when consent is needed.
 *   Receives: { holdId, runId, gapSize, heldEventCount, detectedAt, shield }
 *   The integrator must call gate.resolve(holdId, 'allow'|'deny') when
 *   the human decides.
 * @param {function} [options.onAudit] — Called with audit entry after each
 *   decision. Receives: { holdId, runId, decision, shield, gapSize, eventCount }
 *   If not provided, decisions are not logged (bring your own logger).
 * @param {number} [options.timeout=60000] — Consent timeout in ms.
 *   Default deny after this period. Set to 0 to disable timeout.
 * @param {boolean} [options.greenShield=false] — Enable Green Shield
 *   interception of exec.approval.requested events. When true, Yellow
 *   Shield seq-gap detection is disabled (Green supersedes Yellow).
 * @returns {object} — { inspect, resolve, getState }
 */
function createConsentGate(options) {
  const {
    onConsent,
    onAudit,
    timeout = 60000,
    greenShield = false
  } = options;

  if (typeof onConsent !== 'function') {
    throw new Error('createConsentGate requires an onConsent callback');
  }

  // ── Per-runId sequence tracking (Yellow Shield) ────────────
  // Key: runId, Value: { lastSeq, state, holdId }
  //   state: 'streaming' | 'holding' | 'allowed' | 'denied'
  const runState = new Map();

  // ── Held events buffer ─────────────────────────────────────
  // Key: holdId, Value: { runId, events[], gapSize, detectedAt,
  //   shield, state: 'pending'|'allow'|'deny'|'timeout' }
  const heldEvents = new Map();

  // ── Pending Green Shield approvals ─────────────────────────
  // Key: approvalId, Value: { id, request, holdId, createdAtMs, expiresAtMs }
  const pendingApprovals = new Map();

  /**
   * Resolve a consent decision.
   * 
   * @param {string} holdId — The hold to resolve
   * @param {string} decision — 'allow' | 'deny' | 'timeout'
   * @returns {object|null} — { decision, events[] } on allow, null otherwise.
   *   The caller is responsible for forwarding the returned events.
   */
  function resolve(holdId, decision) {
    const held = heldEvents.get(holdId);
    if (!held) return null;
    if (held.state !== 'pending') return null;

    held.state = decision;

    // Audit callback
    if (typeof onAudit === 'function') {
      onAudit({
        holdId: holdId,
        runId: held.runId,
        decision: decision,
        shield: held.shield,
        gapSize: held.gapSize,
        eventCount: held.events.length
      });
    }

    if (decision === 'allow') {
      const run = runState.get(held.runId);
      if (run) run.state = 'allowed';
      const events = held.events.slice();
      heldEvents.delete(holdId);
      return { decision: 'allow', events: events };
    } else {
      const run = runState.get(held.runId);
      if (run) run.state = 'denied';
      heldEvents.delete(holdId);
      return { decision: decision, events: [] };
    }
  }

  /**
   * Start the consent timeout timer for a hold.
   * @private
   */
  function startTimeout(holdId) {
    if (timeout <= 0) return;
    setTimeout(function() {
      const held = heldEvents.get(holdId);
      if (held && held.state === 'pending') {
        resolve(holdId, 'timeout');
      }
    }, timeout);
  }

  /**
   * Inspect a message from the agent platform.
   * 
   * Call this for every message in the Gateway→Client direction.
   * Returns an action telling the caller what to do.
   * 
   * @param {object} msg — Parsed JSON message from the agent platform
   * @param {Buffer|string} raw — Raw message data for forwarding
   * @param {boolean} isBinary — Whether the message is binary
   * @returns {object} — { action: 'forward'|'hold'|'drop'|'buffer', ... }
   *   'forward': Send to client normally. msg included.
   *   'hold': Consent requested. Do NOT send to client. holdId included.
   *   'drop': Message suppressed (denied run). Do NOT send to client.
   *   'buffer': Added to existing hold. Do NOT send to client.
   */
  function inspect(msg, raw, isBinary) {
    // ── GREEN SHIELD: Intercept exec.approval.requested ──────
    if (msg.type === 'event' && msg.event === 'exec.approval.requested') {
      const approval = msg.payload;
      if (approval && approval.id) {
        const holdId = 'gs-' + crypto.randomUUID().substring(0, 12);

        pendingApprovals.set(approval.id, {
          id: approval.id,
          request: approval.request || {},
          holdId: holdId,
          createdAtMs: approval.createdAtMs || Date.now(),
          expiresAtMs: approval.expiresAtMs || (Date.now() + 60000)
        });

        heldEvents.set(holdId, {
          runId: approval.id,
          events: [],
          gapSize: 0,
          detectedAt: Date.now(),
          shield: 'green',
          state: 'pending',
          approvalId: approval.id
        });

        onConsent({
          holdId: holdId,
          runId: approval.id,
          gapSize: 0,
          heldEventCount: 0,
          detectedAt: Date.now(),
          shield: 'green',
          request: approval.request || {}
        });

        startTimeout(holdId);
        return { action: 'hold', holdId: holdId };
      }
    }

    // Intercept resolved events (don't forward to UI)
    if (msg.type === 'event' && msg.event === 'exec.approval.resolved') {
      return { action: 'drop' };
    }

    // ── YELLOW SHIELD: Seq-gap detection on agent events ─────
    if (!greenShield && msg.type === 'event' && msg.event === 'agent') {
      const payload = msg.payload || {};
      const runId = payload.runId;
      const seq = payload.seq;
      const stream = payload.stream;

      if (runId && typeof seq === 'number') {
        if (!runState.has(runId)) {
          runState.set(runId, { lastSeq: 0, state: 'streaming', holdId: null });
        }
        const run = runState.get(runId);

        // If holding, buffer this event
        if (run.state === 'holding' && run.holdId) {
          const held = heldEvents.get(run.holdId);
          if (held && held.state === 'pending') {
            held.events.push({ data: raw, isBinary: isBinary });
            run.lastSeq = seq;
            return { action: 'buffer', holdId: run.holdId };
          }
        }

        // If denied, drop all further events for this run
        if (run.state === 'denied') {
          run.lastSeq = seq;
          return { action: 'drop' };
        }

        // Seq-gap detection on assistant stream
        if (stream === 'assistant' && run.lastSeq > 0 && seq > run.lastSeq + 1) {
          const gapSize = seq - run.lastSeq - 1;
          const holdId = 'ysh-' + crypto.randomUUID().substring(0, 12);

          run.state = 'holding';
          run.holdId = holdId;
          run.lastSeq = seq;

          heldEvents.set(holdId, {
            runId: runId,
            events: [{ data: raw, isBinary: isBinary }],
            gapSize: gapSize,
            detectedAt: Date.now(),
            shield: 'yellow',
            state: 'pending'
          });

          onConsent({
            holdId: holdId,
            runId: runId,
            gapSize: gapSize,
            heldEventCount: 1,
            detectedAt: Date.now(),
            shield: 'yellow'
          });

          startTimeout(holdId);
          return { action: 'hold', holdId: holdId };
        }

        // Normal event — track and forward
        run.lastSeq = seq;
      }
    }

    // ── Default: forward ─────────────────────────────────────
    return { action: 'forward' };
  }

  /**
   * Get current state for diagnostics.
   * @returns {object} — { activeHolds, trackedRuns, pendingApprovals }
   */
  function getState() {
    return {
      activeHolds: heldEvents.size,
      trackedRuns: runState.size,
      pendingApprovals: pendingApprovals.size
    };
  }

  return { inspect, resolve, getState };
}

module.exports = { createConsentGate };
