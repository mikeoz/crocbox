# CROCbox — The Agent Trust Layer for OpenClaw

**Your AI. Your Control.**

CROCbox wraps [OpenClaw](https://openclaw.ai) in a transparent trust layer. When your AI executes an action, CROCbox detects it, holds the result, and asks you: **Allow or Block?**

This is the Agent Trust Layer. It works today.

## What CROCbox Does

You run OpenClaw — the open-source AI agent platform. OpenClaw is powerful. It executes shell commands, reads files, searches the web, and more. But right now, it does all of that without asking you first.

CROCbox changes that.

CROCbox sits between you and OpenClaw as an invisible proxy. It sees every action your AI takes. When a tool executes, CROCbox intercepts the result and shows you a consent card: **Allow Result** or **Block Result**. You decide what reaches you. Every decision is logged in a tamper-evident audit trail with SHA-256 hash chain.

No changes to OpenClaw. No plugins to install. No configuration files to edit. Just download, drag to Applications, and double-click.

## The Shield System

CROCbox uses a three-level shield system to be honest about what it can and cannot control:

**🟡 Yellow Shield — Consent Before Delivery** (current)
Your AI's action has already executed. CROCbox controls whether the *result* reaches you. You see every action. You choose what gets delivered. This is what CROCbox ships with today, because OpenClaw doesn't yet provide pre-execution consent hooks for desktop clients.

**🟢 Green Shield — Consent Before Execution** (ready, waiting on OpenClaw)
The action is intercepted *before* it runs. CROCbox decides whether it executes at all. The code for this is written and waiting. It activates the moment OpenClaw enables `exec.approval.requested` broadcasts for `openclaw-macos` clients.

**🔴 Red Shield — No External Consent**
The platform provides no consent mechanism. CROCbox informs you but cannot intervene. This is the label for platforms that don't support any form of external consent.

## Install

### Requirements
- macOS 12 or later (Apple Silicon)
- [OpenClaw](https://openclaw.ai) installed and running

### Steps
1. Download `CROCbox-0.8.0-alpha-arm64.dmg` from [Releases](https://github.com/mikeoz/crocbox/releases)
2. Mount the DMG
3. Drag CROCbox to Applications
4. Start OpenClaw Gateway: `openclaw gateway`
5. Double-click CROCbox

No Terminal required after step 4. No configuration files. No API keys to paste.

## What You'll See

1. CROCbox opens showing the OpenClaw interface — your existing chats, sessions, and settings are all there
2. Ask your AI to do something that requires a tool: *"Run the command: date"*
3. The **Yellow Shield** consent card slides in from the right
4. Click **Allow Result** to see the output, or **Block Result** to suppress it
5. Every decision is recorded in the audit log at `~/opnli/crocbox/logs/crocbox-audit.jsonl`

## How It Works

CROCbox is an Electron application that creates a WebSocket man-in-the-middle proxy between OpenClaw's Control UI and its Gateway. The proxy:

1. **Relays all messages transparently** — the user experience is unchanged
2. **Tracks sequence numbers** in the agent event stream per run
3. **Detects sequence gaps** — when OpenClaw's agent executes a tool, the node-host consumes tool events internally, creating a gap in the sequence (e.g., seq 1 → seq 5)
4. **Holds the first assistant event** after the gap — this is the tool's result
5. **Shows the consent card** and waits for the user's decision
6. **Forwards or drops** the held events based on Allow/Deny/Timeout
7. **Logs every decision** to a tamper-evident audit trail

The proxy adds zero latency to normal conversation. It only activates when a tool executes.

## For the OpenClaw Community

CROCbox exists because we believe AI agents should ask before they act — or at minimum, before they deliver results. OpenClaw is the most powerful open-source agent platform available. CROCbox makes it the most trustworthy.

**Yellow Shield is honest.** It tells you the action already ran. It doesn't pretend to block execution when it can't. But it proves that consent enforcement is possible, practical, and invisible to the user experience.

**Green Shield is ready.** The code to intercept `exec.approval.requested` broadcasts and call `exec.approval.resolve` is in `ws-proxy.js` today. If OpenClaw enables these broadcasts for `openclaw-macos` clients, CROCbox upgrades to full Consent Before Execution with zero code changes.

We'd love to work with the OpenClaw Foundation to make Green Shield a reality. The Agent Trust Layer is a standard that makes every AI agent safer — not just on OpenClaw, but everywhere.

## Architecture

```
Electron Main Process (main.js)
├── Gateway health check (port 18789)
├── WebSocket connection (openclaw-macos, token auth)
├── ws-proxy.js (port 18788)
│   ├── HTTP proxy: auth injection + WS redirect
│   ├── WS relay: transparent bidirectional
│   ├── Seq-gap detection: per-runId tracking
│   ├── Consent hold: event buffering
│   └── Audit logger: SHA-256 hash chain
├── BrowserWindow → OpenClaw Control UI (via proxy)
└── IPC bridge: consent card ↔ proxy
```

## About

CROCbox is built by [Opn.li](https://opn.li) (Openly Personal Networks, Inc.) as part of the Agent Trust Layer initiative. The ATL defines a standard for human consent enforcement in AI agent systems: **Know. Choose. Check.**

- **Know**: The shield color tells you what level of consent is possible
- **Choose**: The consent card lets you Allow or Block
- **Check**: The audit log records every decision with cryptographic integrity

*My data + Your AI + My control = Living Intelligence*

## License

See [LICENSE](LICENSE) for details.
