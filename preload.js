/**
 * CROCbox v0.9 — Electron Preload Script
 * 
 * A.7: Auth token auto-injection
 * A.11: Yellow Shield consent card IPC bridge
 * 
 * This script runs in the renderer process BEFORE the Control UI loads.
 * It bridges IPC between the Electron main process and the renderer.
 * 
 * A.7: Receives the Gateway auth token from main process via IPC
 * and writes it into localStorage (NOTE: now handled by proxy HTML
 * injection — this listener is kept as fallback).
 * 
 * A.11: Receives consent requests from main process (forwarded from
 * ws-proxy.js seq-gap detection) and exposes them to the renderer.
 * The renderer shows the Yellow Shield consent card and sends the
 * user's decision back via resolveConsent().
 * 
 * @see OPN_ENG_A10-YellowShield_18MAR26_v1
 * @see OPN_ENG_v08-Architecture_15MAR26_v1, Section 3.3
 * @see OPN_PM_FullCROC-Mode_16MAR26_v2, Section 2.2, 4.2
 */
const { contextBridge, ipcRenderer } = require('electron');
// ── A.7: Auth Token Auto-Injection (fallback) ──────────────────
ipcRenderer.on('crocbox:inject-auth', function(_event, payload) {
  var token = payload.token;
  var deviceId = payload.deviceId;
  if (!token || !deviceId) {
    console.error('[CROCbox Preload] inject-auth received but missing token or deviceId');
    return;
  }
  var authStore = {
    version: 1,
    deviceId: deviceId,
    tokens: {
      operator: {
        token: token,
        role: 'operator',
        scopes: ['operator.admin', 'operator.approvals', 'operator.pairing'],
        updatedAtMs: Date.now()
      }
    }
  };
  try {
    window.localStorage.setItem('openclaw.device.auth.v1', JSON.stringify(authStore));
    console.log('[CROCbox Preload] Auth token injected into localStorage');
  } catch (err) {
    console.error('[CROCbox Preload] Failed to write auth to localStorage:', err.message);
  }
});
// ── A.11: Yellow Shield Consent IPC ────────────────────────────
//
// The consent flow:
//   1. ws-proxy.js detects seq-gap -> calls IPC callback
//   2. main.js sends 'crocbox:consent-request' to this renderer
//   3. Preload receives it -> calls registered callback
//   4. Renderer shows Yellow Shield consent card
//   5. User clicks Allow or Deny
//   6. Renderer calls crocbox.resolveConsent(holdId, decision)
//   7. Preload invokes 'crocbox:consent-resolve' on main process
//   8. main.js calls resolveConsent() on ws-proxy.js
//   9. Proxy forwards (allow) or drops (deny) held events
// Consent request callbacks registered by the renderer
var consentCallbacks = [];
// Listen for consent requests from main process
ipcRenderer.on('crocbox:consent-request', function(_event, consentRequest) {
  console.log('[CROCbox Preload] Consent request received: holdId=' + consentRequest.holdId);
  for (var i = 0; i < consentCallbacks.length; i++) {
    try {
      consentCallbacks[i](consentRequest);
    } catch (err) {
      console.error('[CROCbox Preload] Consent callback error:', err.message);
    }
  }
});
// ── CROCbox Identity + IPC Bridge ──────────────────────────────
contextBridge.exposeInMainWorld('crocbox', {
  // Identity
  version: '1.0.0',
  phase: 'soft-launch',
  isCROCbox: true,
  // A.11: Yellow Shield consent API
  //
  // Register a callback to receive consent requests.
  // callback signature: (consentRequest) => void
  // consentRequest: { holdId, runId, gapSize, heldEventCount, detectedAt }
  onConsentRequest: function(callback) {
    if (typeof callback === 'function') {
      consentCallbacks.push(callback);
      console.log('[CROCbox Preload] Consent callback registered (' + consentCallbacks.length + ' total)');
    }
  },
  // Shield Scoring Engine — get detail HTML for click-through
  getShieldDetail: function() {
    return ipcRenderer.invoke('crocbox:shield-detail');
  },
  // Send consent decision back to main process -> proxy.
  // holdId: string (from consentRequest)
  // decision: 'allow' | 'deny'
  resolveConsent: function(holdId, decision) {
    console.log('[CROCbox Preload] Resolving consent: holdId=' + holdId + ' decision=' + decision);
    return ipcRenderer.invoke('crocbox:consent-resolve', holdId, decision);
  },
  // Account activation — opens opn.li/connect in browser
  activate: function() {
    console.log("[CROCbox Preload] Activation requested");
    return ipcRenderer.invoke("crocbox:activate");
  },
  // Trust Activity viewer
  openTrustActivity: function() {
    return ipcRenderer.invoke("crocbox:trust-activity");
  }
});
console.log('[CROCbox Preload] Preload script loaded (Yellow Shield IPC active)');
