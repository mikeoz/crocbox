/**
 * CROCbox v0.9 — Electron Preload Script
 * 
 * A.7: Auth token auto-injection
 * A.11: Yellow Shield consent card IPC bridge
 * A.12: Green Shield consent card IPC bridge (replaces executeJavaScript)
 * A.12: Trust Bar IPC bridge (replaces executeJavaScript)
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

// ── A.12: Green Shield Consent IPC ─────────────────────────────
//
// The Green Shield consent flow (Consent Before Execution):
//   1. Hook in reply engine calls green-shield-gate.js HTTP server
//   2. Gate calls consentCallback -> main.js
//   3. main.js sends 'crocbox:green-consent-request' to this renderer
//   4. Preload renders Green Shield consent card via DOM
//   5. NHB clicks Allow or Block
//   6. Preload sends decision via ipcRenderer.invoke('crocbox:green-consent-resolve')
//   7. main.js calls resolveGreenConsent() on green-shield-gate.js
//   8. Gate resolves HTTP response -> hook proceeds or blocks

// Green Shield consent request handler — renders card via DOM
ipcRenderer.on('crocbox:green-consent-request', function(_event, data) {
  var requestId = data.requestId;
  var toolName = data.toolName || 'unknown action';
  var toolParams = data.toolParams || {};
  console.log('[CROCbox Preload] Green Shield consent request: ' + toolName + ' id=' + requestId);

  // Build detail string
  var detail = '';
  if (toolParams && typeof toolParams === 'object') {
    if (toolParams.command) detail = toolParams.command;
    else if (toolParams.path || toolParams.filePath) detail = toolParams.path || toolParams.filePath;
    else if (toolParams.query) detail = toolParams.query;
    else if (toolParams.url) detail = toolParams.url;
    else if (toolParams.content) detail = (toolParams.content + '').substring(0, 80);
    else {
      var keys = Object.keys(toolParams).slice(0, 3);
      detail = keys.map(function(k) { return k + ': ' + (toolParams[k] + '').substring(0, 40); }).join(', ');
    }
  }

  // Wait for DOM to be ready
  function renderCard() {
    // Remove any existing card
    var old = document.getElementById('crocbox-consent-overlay');
    if (old) old.remove();

    // Add style if needed
    if (!document.getElementById('crocbox-green-consent-style')) {
      var s = document.createElement('style');
      s.id = 'crocbox-green-consent-style';
      s.textContent = '#crocbox-consent-overlay { position:fixed; top:0; right:0; bottom:0; width:360px; z-index:999999; background:rgba(0,0,0,0.92); border-left:3px solid #2E7D32; font-family:-apple-system,BlinkMacSystemFont,sans-serif; color:#f0f0f0; display:flex; flex-direction:column; } #crocbox-consent-overlay .gs-btn { flex:1; padding:14px 16px; border:none; border-radius:8px; font-size:15px; font-weight:500; cursor:pointer; } #crocbox-consent-overlay .gs-btn-allow { background:#2E7D32; color:#fff; } #crocbox-consent-overlay .gs-btn-deny { background:#333; color:#f0f0f0; border:1px solid #555; }';
      document.head.appendChild(s);
    }

    var overlay = document.createElement('div');
    overlay.id = 'crocbox-consent-overlay';

    // Header
    var header = document.createElement('div');
    header.style.cssText = 'padding:24px 24px 16px; border-bottom:1px solid rgba(46,125,50,0.3)';
    header.innerHTML = '<div style="text-align:center; margin-bottom:8px"><svg width="48" height="58" viewBox="0 0 100 120" style="display:inline-block"><path d="M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z" fill="#1B5E20" stroke="#2E7D32" stroke-width="3"/><path d="M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z" fill="#2E7D32"/><path d="M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z" fill="#4CAF50"/></svg></div><div style="font-size:17px; font-weight:500; color:#4CAF50; margin-bottom:6px">Green Shield</div><div style="font-size:13px; color:#999">Action Requested</div>';
    overlay.appendChild(header);

    // Body
    var body = document.createElement('div');
    body.style.cssText = 'flex:1; padding:20px 24px';

    var desc = document.createElement('div');
    desc.style.cssText = 'font-size:14px; color:#ccc; line-height:1.6; margin-bottom:12px';
    desc.innerHTML = 'Your AI wants to perform an action. It has <strong>NOT executed yet</strong>. You decide.';
    body.appendChild(desc);

    var toolBox = document.createElement('div');
    toolBox.style.cssText = 'background:rgba(46,125,50,0.15); border:1px solid rgba(46,125,50,0.3); border-radius:8px; padding:12px; margin-bottom:12px';
    toolBox.innerHTML = '<div style="font-size:11px; color:#81C784; text-transform:uppercase; margin-bottom:4px">Tool</div><div style="font-size:14px; color:#fff; font-weight:500"></div>';
    toolBox.querySelector('div:last-child').textContent = toolName;
    body.appendChild(toolBox);

    if (detail) {
      var detailBox = document.createElement('div');
      detailBox.style.cssText = 'background:rgba(255,255,255,0.05); border-radius:8px; padding:12px';
      detailBox.innerHTML = '<div style="font-size:11px; color:#999; text-transform:uppercase; margin-bottom:4px">Detail</div><div style="font-size:13px; color:#ccc; word-break:break-all"></div>';
      detailBox.querySelector('div:last-child').textContent = detail;
      body.appendChild(detailBox);
    }
    overlay.appendChild(body);

    // Buttons
    var btnRow = document.createElement('div');
    btnRow.style.cssText = 'padding:16px 24px 24px; display:flex; gap:12px';

    var allowBtn = document.createElement('button');
    allowBtn.className = 'gs-btn gs-btn-allow';
    allowBtn.textContent = 'Allow';
    allowBtn.addEventListener('click', function() {
      console.log('[CROCbox] Green Shield: User clicked ALLOW');
      overlay.remove();
      ipcRenderer.invoke('crocbox:green-consent-resolve', requestId, 'allow');
    });

    var blockBtn = document.createElement('button');
    blockBtn.className = 'gs-btn gs-btn-deny';
    blockBtn.textContent = 'Block';
    blockBtn.addEventListener('click', function() {
      console.log('[CROCbox] Green Shield: User clicked BLOCK');
      overlay.remove();
      ipcRenderer.invoke('crocbox:green-consent-resolve', requestId, 'deny');
    });

    btnRow.appendChild(allowBtn);
    btnRow.appendChild(blockBtn);
    overlay.appendChild(btnRow);

    document.body.appendChild(overlay);
    console.log('[CROCbox] Green Shield consent card rendered for: ' + toolName);
  }

  if (document.body) {
    renderCard();
  } else {
    document.addEventListener('DOMContentLoaded', renderCard);
  }
});

// ── Green Shield Timeout Visual Transition ──────────────────────
ipcRenderer.on('crocbox:green-consent-timeout', function(_event, data) {
  var requestId = data.requestId;
  console.log('[CROCbox Preload] Green Shield timeout received: id=' + requestId);
  var overlay = document.getElementById('crocbox-consent-overlay');
  if (!overlay) {
    console.log('[CROCbox Preload] Timeout: consent card already removed');
    return;
  }
  // Gray out buttons
  var buttons = overlay.querySelectorAll('.gs-btn');
  buttons.forEach(function(btn) {
    btn.disabled = true;
    btn.style.opacity = '0.4';
    btn.style.cursor = 'default';
    btn.style.pointerEvents = 'none';
  });
  // Replace button row content with timeout message
  var btnRow = overlay.querySelector('.gs-btn').parentElement;
  btnRow.innerHTML = '<div style="text-align:center; width:100%"><div style="font-size:14px; color:#FFA726; font-weight:500; margin-bottom:6px">⏱ Timed out — blocked</div><div style="font-size:12px; color:#999">This action was not allowed.</div></div>';
  // Change border to amber
  overlay.style.borderLeft = '3px solid #FFA726';
  // Auto-dismiss after 3 seconds
  setTimeout(function() {
    var el = document.getElementById('crocbox-consent-overlay');
    if (el) {
      el.style.transition = 'opacity 0.3s ease-out';
      el.style.opacity = '0';
      setTimeout(function() {
        var el2 = document.getElementById('crocbox-consent-overlay');
        if (el2) el2.remove();
      }, 300);
    }
  }, 3000);
});

// ── A.12: Trust Bar IPC ────────────────────────────────────────
//
// main.js sends trust bar data via IPC. Preload renders it via DOM.
// No executeJavaScript. No template literal nesting.
// Beta: Trust Bar creates its own panel overlays for Shield Detail and Controls.
ipcRenderer.on('crocbox:trust-bar', function(_event, data) {
  var score = data.score || {};
  var veLabel = data.veLabel || 'Local Mode';
  var isGreen = data.greenShield ? true : false;
  console.log('[CROCbox Preload] Trust Bar data received: greenShield=' + isGreen);
  function renderTrustBar() {
    // Remove existing trust bar
    var old = document.getElementById('crocbox-trust-bar');
    if (old) old.remove();
    // Hide legacy indicators
    var si = document.getElementById('crocbox-shield-icon');
    if (si) si.style.display = 'none';
    var ti = document.getElementById('crocbox-trust-indicator');
    if (ti) ti.style.display = 'none';
    var cb = document.getElementById('crocbox-controls-btn');
    if (cb) cb.style.display = 'none';

    // Determine colors
    var colorHex = isGreen ? '#4CAF50' : '#d4a017';
    var shieldLabel = isGreen ? 'GREEN' : 'YELLOW';
    var veColor = veLabel.includes('Trust Network') ? '#4CAF50' : '#d4a017';
    // SVG colors
    var svgOuter = isGreen ? '#1B5E20' : '#58585C';
    var svgStroke = isGreen ? '#2E7D32' : '#707074';
    var svgMid = isGreen ? '#2E7D32' : '#CA8A04';
    var svgInner = isGreen ? '#4CAF50' : '#EAB308';

    // ── Create Trust Bar ──
    var bar = document.createElement('div');
    bar.id = 'crocbox-trust-bar';
    bar.style.cssText = 'position:fixed; top:0; left:0; right:0; height:38px; z-index:999999; background:#111; border-bottom:1px solid #333; display:flex; align-items:center; justify-content:center; gap:24px; font-family:-apple-system,sans-serif; padding:0 16px;';

    // VE status
    var veDiv = document.createElement('div');
    veDiv.style.cssText = 'display:flex;align-items:center;gap:6px;cursor:default;';
    veDiv.innerHTML = '<span style="font-size:12px;color:' + veColor + ';">\u25CF</span><span style="font-size:12px;color:' + veColor + ';font-weight:500;"></span>';
    veDiv.querySelector('span:last-child').textContent = veLabel;
    bar.appendChild(veDiv);

    // Separator
    var sep1 = document.createElement('div');
    sep1.style.cssText = 'width:1px;height:16px;background:#333;';
    bar.appendChild(sep1);

    // Controls button
    var ctrlDiv = document.createElement('div');
    ctrlDiv.id = 'crocbox-bar-controls';
    ctrlDiv.style.cssText = 'display:flex;align-items:center;gap:5px;cursor:pointer;';
    ctrlDiv.innerHTML = '<span style="font-size:12px;">\u2699\uFE0F</span><span style="font-size:12px;color:#ccc;font-weight:500;">Controls</span>';
    bar.appendChild(ctrlDiv);

    // Separator
    var sep2 = document.createElement('div');
    sep2.style.cssText = 'width:1px;height:16px;background:#333;';
    bar.appendChild(sep2);

    // Shield indicator with SVG
    var shieldDiv = document.createElement('div');
    shieldDiv.id = 'crocbox-bar-shield';
    shieldDiv.style.cssText = 'display:flex;align-items:center;gap:6px;cursor:pointer;';
    shieldDiv.innerHTML = '<svg width="18" height="22" viewBox="0 0 100 120" style="display:inline-block"><path d="M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z" fill="' + svgOuter + '" stroke="' + svgStroke + '" stroke-width="3"/><path d="M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z" fill="' + svgMid + '"/><path d="M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z" fill="' + svgInner + '"/></svg><span style="font-size:11px;color:' + colorHex + ';font-weight:500;">' + shieldLabel + '</span>';
    bar.appendChild(shieldDiv);

    // ── Create Shield Detail panel overlay ──
    var detailPanel = document.getElementById('crocbox-shield-detail');
    if (!detailPanel) {
      detailPanel = document.createElement('div');
      detailPanel.id = 'crocbox-shield-detail';
      detailPanel.style.cssText = 'position:fixed;top:38px;left:50%;transform:translateX(-50%);z-index:999998;background:#1a1a1a;border:1px solid #333;border-radius:8px;max-width:480px;width:90%;max-height:70vh;overflow-y:auto;display:none;box-shadow:0 8px 32px rgba(0,0,0,0.5);font-family:-apple-system,sans-serif;color:#f0f0f0;';
      document.body.appendChild(detailPanel);
    }

    // ── Create Controls panel overlay ──
    var ctrlPanel = document.getElementById('crocbox-controls-panel');
    if (!ctrlPanel) {
      ctrlPanel = document.createElement('div');
      ctrlPanel.id = 'crocbox-controls-panel';
      ctrlPanel.style.cssText = 'position:fixed;top:38px;left:50%;transform:translateX(-50%);z-index:999998;background:#1a1a1a;border:1px solid #333;border-radius:8px;max-width:320px;width:80%;display:none;box-shadow:0 8px 32px rgba(0,0,0,0.5);font-family:-apple-system,sans-serif;color:#f0f0f0;padding:12px 0;';
      var menuItems = [
        { id: 'ctrl-keycard', icon: '\uD83D\uDD11', label: 'keyCARD', ipc: 'crocbox:open-keycard' },
        { id: 'ctrl-activity', icon: '\uD83D\uDCCB', label: 'Trust Activity', ipc: 'crocbox:trust-activity' },
        { id: 'ctrl-trust-model', icon: '\uD83D\uDEE1', label: 'Trust Model', ipc: 'crocbox:open-trust-model' },
        { id: 'ctrl-about', icon: '\u2139\uFE0F', label: 'About CROCbox', ipc: 'crocbox:open-about' },
        { id: 'ctrl-model', icon: '\uD83E\uDD16', label: 'Switch Model', ipc: 'crocbox:switch-model-picker' }
      ];
      menuItems.forEach(function(item) {
        var row = document.createElement('div');
        row.id = item.id;
        row.style.cssText = 'padding:8px 16px;cursor:pointer;font-size:13px;';
        row.textContent = item.icon + ' ' + item.label;
        row.addEventListener('mouseover', function() { row.style.background = '#333'; });
        row.addEventListener('mouseout', function() { row.style.background = 'transparent'; });
        row.addEventListener('click', function() {
          ctrlPanel.style.display = 'none';
          console.log('[CROCbox] Controls: clicked ' + item.label + ' -> ' + item.ipc);
          ipcRenderer.invoke(item.ipc);
        });
        ctrlPanel.appendChild(row);
      });
      document.body.appendChild(ctrlPanel);
    }

    // ── Wire Controls click ──
    ctrlDiv.addEventListener('click', function(ev) {
      ev.stopPropagation();
      var p = document.getElementById('crocbox-controls-panel');
      if (p) {
        p.style.display = p.style.display === 'none' ? 'block' : 'none';
        var sd = document.getElementById('crocbox-shield-detail');
        if (sd) sd.style.display = 'none';
      }
    });

    // ── Wire Shield click ──
    shieldDiv.addEventListener('click', function(ev) {
      ev.stopPropagation();
      var d = document.getElementById('crocbox-shield-detail');
      if (d) {
        if (d.style.display !== 'none' && d.innerHTML !== '') {
          d.style.display = 'none';
        } else {
          if (window.crocbox && window.crocbox.getShieldDetail) {
            window.crocbox.getShieldDetail().then(function(html) {
              d.innerHTML = html + '<div style="padding:8px 20px 16px;text-align:center;border-top:1px solid #333"><a id="crocbox-detail-close" href="#" style="color:#888;font-size:11px;text-decoration:none;cursor:pointer">Close</a></div>';
              setTimeout(function() {
                var cl = document.getElementById('crocbox-detail-close');
                if (cl) cl.addEventListener('click', function(e) { e.preventDefault(); d.style.display = 'none'; });
              }, 50);
              d.style.display = 'block';
            });
          }
        }
        var cp = document.getElementById('crocbox-controls-panel');
        if (cp) cp.style.display = 'none';
      }
    });

    // ── Insert bar and push content down ──
    document.body.prepend(bar);
    document.body.style.marginTop = '38px';

    // Close panels on outside click
    document.addEventListener('click', function(ev) {
      var p = document.getElementById('crocbox-controls-panel');
      var d = document.getElementById('crocbox-shield-detail');
      var barC = document.getElementById('crocbox-bar-controls');
      var barS = document.getElementById('crocbox-bar-shield');
      if (p && p.style.display !== 'none' && !p.contains(ev.target) && (!barC || !barC.contains(ev.target))) {
        p.style.display = 'none';
      }
      if (d && d.style.display !== 'none' && !d.contains(ev.target) && (!barS || !barS.contains(ev.target))) {
        d.style.display = 'none';
      }
    });

    // Re-inject if SPA destroys it
    var barObserver = new MutationObserver(function() {
      if (!document.getElementById('crocbox-trust-bar')) {
        console.log('[CROCbox] Trust bar destroyed by SPA - re-injecting');
        setTimeout(function() {
          if (!document.getElementById('crocbox-trust-bar')) {
            document.body.prepend(bar);
            document.body.style.marginTop = '38px';
          }
        }, 200);
      }
    });
    barObserver.observe(document.body, { childList: true, subtree: false });
    console.log('[CROCbox] Trust bar rendered via IPC');
  }

  if (document.body) {
    renderTrustBar();
  } else {
    document.addEventListener('DOMContentLoaded', renderTrustBar);
  }
});

// ── CROCbox Identity + IPC Bridge ──────────────────────────────
contextBridge.exposeInMainWorld('crocbox', {
  // Identity
  version: '1.0.0-beta.1',
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
  },
  // keyCARD — manage API keys
  openKeyCARD: function() {
    return ipcRenderer.invoke("crocbox:open-keycard");
  },
  // Trust Model — view Trust.md
  openTrustModel: function() {
    return ipcRenderer.invoke("crocbox:open-trust-model");
  },
  // About CROCbox
  openAbout: function() {
    return ipcRenderer.invoke("crocbox:open-about");
  }
});
console.log('[CROCbox Preload] Preload script loaded (Yellow Shield + Green Shield + Trust Bar IPC active)');
