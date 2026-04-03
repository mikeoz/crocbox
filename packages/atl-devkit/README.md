# @opnli/atl-devkit

**Add human consent to any AI agent in 3 lines.**

The Agent Trust Layer (ATL) DevKit gives developers a drop-in consent
gate for AI agents. When your agent tries to act on the world — read a
file, call an API, run a command — the ATL holds the action and asks the
human: **Allow or Block?**

The human's decision is final. The audit trail is tamper-evident.
There is no bypass.

## Quick Start

    const { createConsentGate } = require('@opnli/atl-devkit');
    const gate = createConsentGate({ onConsent: askTheHuman, timeout: 60000 });
    myProxy.onMessage((msg, raw) => {
      const result = gate.inspect(msg, raw, false);
      if (result.action === 'forward') send(raw);
      // 'hold' means consent requested. Wait for gate.resolve(holdId, 'allow'|'deny')
    });

## Why This Exists

AI agents are getting powerful. They can read your files, search the
web, execute code, and call APIs — often without asking. The industry
is moving fast on capability. Nobody is moving on trust.

The ATL is the trust layer. It does not slow agents down. It puts the
human in control of what agents do. **Be the enabler for the timid.
Never be the barrier to the powerful.**

## The Three Realities of Trust

Every trust decision involves three realities:

1. **Identity** — Know who is acting. (CARD credentials)
2. **Consent** — Choose what is allowed. (This DevKit)
3. **Accountability** — Check what happened. (Audit log)

The DevKit delivers Consent and Accountability. Identity comes from
the Opn.li Trust Network (https://opn.li) via CARD credentials.

## Two Shield Levels

### Green Shield — Consent Before Execution

The agent requests permission to act. The action has **NOT happened
yet**. The human decides whether it happens. This requires the agent
platform to support pre-execution approval events.

    Agent: "I want to run: npm install express"
      -> ATL HOLDS the request
      -> Human sees: "Your AI wants to run a shell command: npm install express"
      -> Human clicks Allow -> command executes
      -> Human clicks Block -> command never runs

### Yellow Shield — Consent Before Delivery

The agent executed an action, but the result has not been delivered to
the UI. The ATL detects the execution via a sequence gap in the event
stream and holds the result. The human decides whether to receive it.

This works on **any platform** that streams sequential agent events —
no platform modifications required.

    Agent executes a tool (seqs 2-4 consumed internally)
      -> ATL detects gap: seq jumped from 1 to 5
      -> ATL HOLDS the result
      -> Human sees: "Your AI executed an action. Allow the result?"
      -> Human clicks Allow -> result delivered
      -> Human clicks Block -> result dropped, agent notified

## API

### createConsentGate(options)

Create a consent gate for an agent message stream.

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| onConsent | function | *required* | Called when consent is needed. Receives { holdId, runId, gapSize, shield, request }. |
| onAudit | function | null | Called after each decision with { holdId, runId, decision, shield, gapSize, eventCount }. |
| timeout | number | 60000 | Consent timeout in ms. Default deny after expiry. 0 to disable. |
| greenShield | boolean | false | Enable Green Shield. When true, Yellow Shield is disabled. |

**Returns:** { inspect, resolve, getState }

#### gate.inspect(msg, raw, isBinary)

Inspect a message from the agent platform. Call for every Gateway-to-Client message.

Returns { action } where action is:
- "forward" — Send to client normally
- "hold" — Consent requested. Do NOT send. Includes holdId.
- "drop" — Suppressed. Do NOT send.
- "buffer" — Added to existing hold. Do NOT send.

#### gate.resolve(holdId, decision)

Resolve a consent decision. decision is "allow", "deny", or "timeout".

Returns { decision, events[] } — on allow, events contains the held
messages to forward. On deny/timeout, events is empty.

### createAuditLogger(logPath)

Create a tamper-evident audit logger.

**Returns:** { writeEntry, verifyChain }

#### logger.writeEntry(opts)

Append a consent decision. opts: { holdId, runId, decision, shield, gapSize, eventCount }.

#### logger.verifyChain()

Verify hash chain integrity. Returns { valid, entries, brokenAt }.

## Design Principles

- **Non-invasive.** The ATL wraps agent platforms. It does not modify them.
- **Fail-closed.** No response = no permission. Connection drop = denied.
- **Platform-agnostic.** Works with any agent that streams sequential events.
- **Honest.** Yellow Shield is consent before delivery, not before execution. We say so.
- **Auditable.** Every decision is logged with a SHA-256 hash chain.

## License

Apache-2.0 — Openly Personal Networks, Inc. (https://opn.li)

## The Agent Economy

*My data + Your AI + My control = Living Intelligence*

CROCbox is the reference implementation of the ATL. The DevKit is how
every developer brings trust to their own agents. Together, we are
building the Agent Economy — where humans control what AI does, not
the other way around.

Learn more at https://opn.li