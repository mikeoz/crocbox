/**
 * @opnli/atl-devkit — The Agent Trust Layer DevKit
 * 
 * Add human consent to any AI agent in 3 lines.
 * 
 *   const { createConsentGate } = require('@opnli/atl-devkit');
 *   const gate = createConsentGate({ onConsent: showMyUI, timeout: 60000 });
 *   myProxy.onMessage(gate.inspect);
 * 
 * The Agent Trust Layer sits between an AI agent and the world it acts
 * upon. When the agent tries to act — read a file, call an API, run a
 * command — the ATL holds the action and asks the human: Allow or Block?
 * 
 * The human's decision is final. The audit trail is tamper-evident.
 * There is no bypass. This is trust infrastructure for the Agent Economy.
 * 
 * Two shield levels:
 * 
 *   GREEN SHIELD — Consent Before Execution. The action has NOT happened
 *   yet. The human decides whether it happens. Requires agent platform
 *   support for pre-execution approval events.
 * 
 *   YELLOW SHIELD — Consent Before Delivery. The action HAS happened,
 *   but the result has not been delivered. The human decides whether to
 *   receive it. Works on ANY platform that streams sequential events.
 * 
 * Three Realities of Trust:
 *   1. Identity — Know who is acting (CARD credentials)
 *   2. Consent — Choose what is allowed (this DevKit)
 *   3. Accountability — Check what happened (audit log)
 * 
 * My data + Your AI + My control = Living Intelligence
 * 
 * @see https://github.com/opnli/agent-trust-layer
 * @see https://opn.li
 * 
 * Copyright (c) 2026 Openly Personal Networks, Inc.
 * Licensed under Apache-2.0
 */
'use strict';

const { createConsentGate } = require('./consent-gate');
const { createAuditLogger } = require('./audit-logger');

module.exports = {
  createConsentGate,
  createAuditLogger
};
