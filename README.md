# CROCbox

**The reference implementation of the Human Consent Layer for OpenClaw agents.**

CROCbox wraps any OpenClaw installation in a consent layer that asks before every action. The AI tells you what it wants to do. You decide. Nothing happens without your approval.

## What It Does

1. **Your AI wants to act.** Search the web, run commands, read files — real actions on your computer.
2. **CROCbox asks you first.** Every action is intercepted before it happens. The Green Shield appears.
3. **You decide.** Allow or block. Nothing happens without your approval.

## The Five Choices

When the Green Shield fires, you have five options:

- **Allow once** — this time only
- **Allow until I change it** — a standing rule you can revoke anytime
- **Set a time limit** — allow for 1 hour, 4 hours, 1 day, 1 week, or 30 days
- **No** — block this one action
- **Never allow this** — a standing rule that blocks this action permanently

## The Consent Chain

Every decision — allow or block — is recorded in a tamper-evident SHA-256 hash chain. Each entry links to the previous one. You can see your full history in Trust Activity. If the chain write fails, the receipt honestly says "Decision made but NOT recorded."

## Architecture

Electron Main Process
├── Gateway health check (is OpenClaw running?)
├── WebSocket connection to Gateway
├── ws-proxy.js (HTTP + WebSocket relay to Gateway)
│ └── Injects auth token + WebSocket redirect
├── green-shield-gate.js (Consent Before Execution gate)
│ └── Submits holds to Consent Server
│ └── Waits for NHB decision
│ └── Resolves hold + writes local audit
├── shield-score.js (OWASP + AWS + Meta scoring)
├── agent-sync.js (forwards decisions to opn.li)
├── card_ve_client.js (Verification Endpoint enrollment)
└── preload.js (Green Shield panel + Trust Bar in renderer)


## The Human Consent Layer

CROCbox implements the [Human Consent Layer](https://github.com/mikeoz/human-consent-layer) specification:

- **Consent Before Execution** — every tool call is intercepted before it runs
- **Five-choice consent** — not just allow/deny, but standing rules and time limits
- **Fail-closed** — if consent cannot be obtained, the action is blocked
- **Tamper-evident audit** — SHA-256 hash chain records every decision
- **Standing rules** — create, honor, review, and revoke
- **Honest receipts** — shows what happened and what it didn't do

## Getting Started

1. Download the latest DMG from [Releases](https://github.com/mikeoz/crocbox/releases)
2. Drag CROCbox to Applications
3. Launch — it will find or install OpenClaw automatically
4. Activate with your [opn.li](https://opn.li) account
5. Chat with your AI — the Green Shield fires on every tool call

## Building from Source

```bash
git clone https://github.com/mikeoz/crocbox.git
cd crocbox
npm install
npx electron-builder --mac
```

The DMG will be in `dist/`. Sign and notarize with your own Developer ID for distribution.

## Configuration

CROCbox reads its consent credentials from `~/Library/Application Support/CROCbox/.env`:

- `CONSENT_SERVER_URL` — the consent server endpoint
- `CONSENT_SUBMIT_SECRET` — the agent's bearer token
- `CROCBOX_MEMBER_ID` — the member's UUID

These are written automatically during activation.

## Part of the Open Consent Project

CROCbox is the desktop agent implementation of the [Open Consent](https://github.com/mikeoz/open-consent) umbrella project:

- [human-consent-layer](https://github.com/mikeoz/human-consent-layer) — HCL spec, CARD schemas, ATL DevKit
- [hcl-devkit](https://github.com/mikeoz/hcl-devkit) — VE client, audit chain library, schema validators
- [webmcp-hcl](https://github.com/mikeoz/webmcp-hcl) — WebMCP + HCL consent gate bridge
- [mydatabkt](https://github.com/mikeoz/mydatabkt) — consent-gated personal data bucket
- **crocbox** (this repo) — reference HCL implementation for OpenClaw

## Patent Notice

See [NOTICE](NOTICE) for patent information.

## License

Apache 2.0. See [LICENSE](LICENSE).

---

*My data + Your AI + My control = Living Intelligence*
