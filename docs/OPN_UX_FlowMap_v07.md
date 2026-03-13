# CROCbox v0.7 — UX Flow Map

**Document:** OPN_UX_FlowMap_v07.md
**Date:** March 13, 2026
**Author:** ENG (Technical Architect)
**Purpose:** Captures every user-visible screen, transition, and decision point in CROCbox v0.7. Serves as the skeleton for the User Guide, Agent-Safe Community documentation, and Magic Moment demo script.
**Status:** Living document — updated as WPs complete.

---

## The Formula

**My data + Your AI + My control = Living Intelligence**

Everything the user sees maps to one of these three:

| Formula Element | Building Metaphor | CROCbox Feature |
|---|---|---|
| My data | Rooms in your building | Data Rooms (Desktop, Documents, Downloads) |
| Your AI | A visitor who wants to help | OpenClaw agent (Claude, GPT, etc.) |
| My control | The front door, the locks, the cameras | Consent cards, Deny, Close the Door, Audit Log |

---

## Flow 1: First Launch (Double-Click → Dashboard)

### Screen 1.1: Launch Screen (WP-4 — not yet built)
- **What the user sees:** CROCbox logo, three status dots (CARD Proxy, Gateway, Dashboard), progress bar
- **What's happening:** Three services starting in sequence
- **User action:** Wait. Auto-redirects when all services are ready.

### Screen 1.2: Welcome — Account (Step 0 → Step 1)
- **What the user sees:** "Welcome to CROCbox" with Create Account / Sign In buttons
- **What's happening:** Nothing yet — pure UI
- **User action:** Create account or sign in

### Screen 1.3: Data Room Setup (Step 2)
- **What the user sees:** "Set up your first Data Room" — name, sensitivity, rules
- **What's happening:** Creates a CARD credential for the data room
- **User action:** Create a Data Room or skip
- **Building metaphor:** "You're registering the rooms in your building"

### Screen 1.4: AI Service Connection (Step 3)
- **What the user sees:** Provider list (Anthropic free for alpha, OpenAI, xAI, DeepSeek, Ollama)
- **What's happening:** Writes AI_PROVIDER and API key to local .env
- **User action:** Select provider, paste API key (or use free Anthropic), or skip

### Screen 1.5: Comfort Level — Rental Ski (Step 3b) ✅ WP-5
- **What the user sees:** Three cards: Beginner (green), Intermediate (yellow), Expert (red)
- **What's happening:** Writes CROC_LEVEL to .env, which controls the tool whitelist
- **User action:** Select a level. Beginner pre-selected as default.
- **Building metaphor:** "How many keys do you want to hand out?"

| Level | What your AI can request | Session memory |
|---|---|---|
| Beginner | Web search | None — every action asks fresh |
| Intermediate | Web search + read files | "Remember for this session" option |
| Expert | Web + read + write + run commands | "Trust this tool type" option |

- **Not shown:** Partner level exists but is provisioned by Opn.li for B2B, not user-selectable

### Screen 1.6: All Set (Step 4)
- **What the user sees:** Checklist with green checks, "You are in control" message, "Go to My Dashboard" button
- **What's happening:** First-run complete
- **User action:** Click to enter Dashboard

---

## Flow 2: Magic Moment — Phase 1 (Desktop Scan)

### Screen 2.1: Chat Mode (Default)
- **What the user sees:** Compact chat interface, status bar says "CROCbox is watching. You're in control."
- **What's happening:** Dashboard is idle, all services running
- **User action:** Click "Scan My Desktop" button (or type in chat)

### Screen 2.2: Consent Card — Desktop Scan ✅ WP-1
- **What the user sees:** Consent card appears:
  - Header: "CROCBOX — ACTION INTERCEPTED"
  - Headline: "Your AI wants to read a file on your system"
  - Target: ~/Desktop (monospace)
  - Summary: "Scan your Desktop folder"
  - Allow (green) / Deny (red) buttons
  - Timeout bar counting down (30s for Beginner)
  - Footer: "CROCbox intercepted this before any data was sent. Your choice."
- **What's happening:** CARD Proxy received a consent_request via WebSocket, Dashboard is rendering real consent card, NO data has been read yet
- **User action:** Allow, Deny, or let it timeout

### Screen 2.3a: Allow → Scan Results
- **What the user sees:** Desktop file summary — categories, counts, organization suggestions
- **What's happening:** fs.readdirSync executed AFTER consent, results categorized and displayed
- **Audit log entry:** `{ action: 'filesystem-read', target: '~/Desktop', result: 'allowed', reason: 'magic-scan-consent:allow' }`

### Screen 2.3b: Deny → Respectful Acknowledgment
- **What the user sees:** "Denied — I respect your choice completely."
- **What's happening:** Nothing was read. The scan never executed.
- **Audit log entry:** `{ action: 'filesystem-read', target: '~/Desktop', result: 'blocked', reason: 'magic-scan-consent:deny' }`

### Screen 2.3c: Timeout → Access Denied
- **What the user sees:** "Timed out — access denied."
- **What's happening:** Timer expired, treated as deny
- **Audit log entry:** `{ action: 'filesystem-read', target: '~/Desktop', result: 'blocked', reason: 'magic-scan-consent:timeout' }`

**Key point for User Guide:** In all three cases, the audit log recorded what happened. Nothing was hidden. The user can verify this in the Activity tab.

---

## Flow 3: Phase 2 — Agent Conversation with Tool Use

### Screen 3.1: User Types a Prompt
- **What the user sees:** Chat input, types something like "What's happening in the news today?"
- **What's happening:** Prompt sent to OpenClaw agent (Claude via Anthropic API)

### Screen 3.2: Agent Requests a Tool
- **What the user sees:** Agent says "Let me search for that — you'll see a permission request from CROCbox"
- **What's happening:** Claude returned a tool_use block (e.g., web_search). The agentic loop in server.js detected it.

### Screen 3.3: Consent Card — Tool-Specific ✅ WP-3
- **What the user sees:** Consent card with tool-specific language:

| Tool | Headline | Target shown |
|---|---|---|
| web_search | "Your AI wants to search the web" | The search query |
| filesystem_read | "Your AI wants to read a file on your system" | Full file path |
| filesystem_write | "Your AI wants to write a file to your system" | Proposed file path |
| shell_exec | "Your AI wants to run a command on your system" | The exact command + warning |

- **What's happening:** CARD Proxy holding the request. Dashboard rendering consent. No action taken yet.
- **User action:** Allow / Deny / Timeout
- **Data Room context:** If the target is inside a Data Room, the card shows which room. If outside all rooms, a stronger warning appears.

### Screen 3.4: Tool Execution or Denial
- Same pattern as Flow 2: Allow → execute and show results, Deny → respectful message, Timeout → denied
- Agent receives the tool result (or denial message) and continues the conversation

---

## Flow 4: My Data — Data Rooms ✅ WP-6

### Screen 4.1: My Data Tab
- **What the user sees:** Grid of Data Room cards — Desktop, Documents, Downloads (defaults), plus any custom rooms
- **What's happening:** Dashboard fetches room list from /api/data-rooms, enriches with file counts
- **User action:** Click a room to see details, or add a custom room

### Screen 4.2: Room Detail Overlay
- **What the user sees:** Room name, path, file count, open/closed status, access history from audit log
- **What's happening:** Dashboard fetches room history from /api/data-rooms/history, shows recent access decisions
- **Building metaphor:** "Security camera footage for this room"

### Screen 4.3: Close the Door
- **What the user sees:** Red "Close the Door" button
- **What's happening:** Sets room.closed = true in data-rooms.json. All future access to files in this room is auto-denied. Session grants revoked.
- **User action:** Click to close. Can re-open anytime with "Open the Door" (teal button).
- **Building metaphor:** "Change the locks. No one gets in until you say so."

### Screen 4.4: Add Custom Room
- **What the user sees:** Name and path inputs, "Add Room" button
- **What's happening:** Adds a new entry to data-rooms.json, Proxy immediately recognizes it for scope enforcement
- **Building metaphor:** "Register a new room in your building"

---

## Flow 5: Settings — Change Comfort Level ✅ WP-5

### Screen 5.1: Settings → Comfort Level
- **What the user sees:** Dropdown with current level, Save button
- **What's happening:** Reads CROC_LEVEL from .env via /api/config
- **User action:** Change level, click Save

### Screen 5.2: Upgrade Confirmation
- **What the user sees:** "Upgrade to [level]? This enables more powerful tools." confirmation dialog
- **What's happening:** Nothing yet — waiting for confirmation
- **User action:** Confirm or cancel
- **Note:** Downgrade is immediate, no confirmation needed

---

## Flow 6: Audit Log (WP-7 — not yet built)

### Screen 6.1: Activity Tab
- **What the user sees:** Chronological list of all consent decisions — action type, target, decision, timestamp
- **What's happening:** Reads from crocbox-audit.jsonl
- **Filters:** By action type, by decision (allowed/blocked), by Data Room, by time range
- **Live mode:** Auto-refreshes every 5 seconds
- **Building metaphor:** "Review the security camera footage"

### Key audit entry fields:
- `action`: filesystem-read, filesystem-write, shell_exec, api_call
- `target`: the path, URL, or command
- `result`: allowed, blocked, completed
- `reason`: the consent decision source (user-consent, session-grant, room-closed, timeout)
- No `demo: true` — all entries are real ✅ WP-1

---

## Invariant: The Audit Never Lies

Every flow above produces audit entries. The user can always verify:
- What was requested
- What was decided
- Who decided (user consent, session grant, auto-deny, timeout)
- What happened after

This is the "security camera" promise. It is the foundation of trust.

---

## Document Outputs This Flow Map Supports

| Output | Audience | Tone | Source Flows |
|---|---|---|---|
| **User Guide** | NHBs (Normal Human Beings) | Friendly, building metaphor, no jargon | All flows, plain English |
| **Agent-Safe Community Doc** | Developers, AI safety community | Technical but accessible, CARD protocol details | Flows 2-3 (consent mechanics), Flow 4 (Data Rooms) |
| **Magic Moment Demo Script** | Alpha testers, demo audiences | Step-by-step walkthrough, 60-second target | Flow 1 (abbreviated) → Flow 2 → Flow 3 |
| **B2B Partner Guide** | Hosting partners | Business + technical, Data Room / Partner level | Flow 4, Partner level from Flow 1.5 |

---

*My data + Your AI + My control = Living Intelligence*

*OPN_UX_FlowMap_v07 | Opn.li / Openly Trusted Services | Confidential*
