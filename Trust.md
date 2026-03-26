# Trust.md — CROCbox Trust Model
# Managed by CROCbox (Opn.li). This document defines the trust rules CROCbox enforces.
# Users can read this document. Modifications are managed through CROCbox updates.
# Version: 1.0.0 | 2026-03-26

## Consent Model

CROCbox enforces Consent Before Delivery (Yellow Shield).

When the AI agent executes an action through OpenClaw, CROCbox intercepts the
result before it reaches the user. The user reviews the result and decides:
Allow or Block. The result is not delivered until the user decides.

- Agent actions execute through the OpenClaw platform
- CROCbox detects action execution via event stream monitoring
- Results are held pending user consent
- Allow: result is delivered to the conversation
- Block: result is dropped and never delivered

## Fail-Closed Invariants

The system always fails safe. It never fails open.

- Timeout with no user response: Block
- Loss of connection to consent interface: Block
- Unexpected error during consent flow: Block
- Unknown or unrecognized action type: Block

## The Three Powers

These are the rights CROCbox guarantees to the user:

- Know: Full transparency into every action the agent takes.
  The user sees what the agent did, what it targeted, and what it produced.

- Choose: The user's authority is final.
  Allow, block, or ignore. The agent cannot override, bypass, or reinterpret
  the user's decision. Deny means deny.

- Check: Tamper-evident audit trail of every decision.
  Every consent event is logged with a SHA-256 hash chain. Each entry links
  to the previous entry. The chain cannot be altered without detection.

## Shield Levels

CROCbox supports three shield levels. The active level determines when
the user's consent is requested.

- Green Shield: Consent Before Execution
  The agent asks the user BEFORE performing an action.
  The action does not execute until the user approves.
  Status: Future (requires platform support for pre-execution hooks)

- Yellow Shield: Consent Before Delivery [ACTIVE]
  The agent acts. CROCbox catches the result. The user reviews and decides.
  The result is not delivered until the user allows it.

- Red Shield: Emergency Stop
  All agent actions are blocked. No results are delivered.
  Available at any time via the Shield control.

## Audit Requirements

Every consent decision produces an audit log entry containing:

- Timestamp (ISO 8601)
- Action type (yellow-shield, keycard-save, etc.)
- Target (what was acted upon)
- Result (allowed, blocked)
- Reason (user-consent, user-deny, user-timeout, connection-loss)
- Decision identifier
- Shield level at time of decision
- SHA-256 hash linking to previous entry

Audit log location: ~/Library/Application Support/CROCbox/logs/

## Core Invariant

User consent cannot be bypassed, overridden, or reinterpreted by the agent,
by the AI provider, or by CROCbox itself. The trust layer is independent of
the AI. The fox does not guard the henhouse.

---

My data + Your AI + My control = Living Intelligence

Trust.md v1.0.0 | CROCbox | Opn.li / Openly Trusted Services
