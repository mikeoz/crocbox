/**
 * CROCbox — Electron Preload Script
 * OTN-Connected (v4) — Blended Green Shield Panel, August 15, 2026
 * 
 * A.7: Auth token auto-injection
 * A.12: Green Shield blended consent panel (Guarded → Asking → Receipt)
 * A.12: Trust Bar IPC bridge
 * 
 * This script runs in the renderer process BEFORE the Control UI loads.
 * It bridges IPC between the Electron main process and the renderer.
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

// ── A.12: Blended Green Shield Panel ───────────────────────────
//
// Three states:
//   A — Guarded: no pending hold, shield is watching
//   B — Asking: a consent hold is active, NHB must decide
//   C — Receipt: decision made, showing what happened
//
// Matches AgentChatPanel.tsx from the web member app.

var gsState = { current: 'guarded', pending: null, receipt: null, countdown: 0, countdownTimer: null, scopeOpen: false };
var GS_COUNTDOWN_SECONDS = 90;

function getGreenShieldSVG(size, color) {
  var fill1 = color === 'red' ? '#7F1D1D' : '#1B5E20';
  var stroke1 = color === 'red' ? '#991B1B' : '#2E7D32';
  var fill2 = color === 'red' ? '#DC2626' : '#2E7D32';
  var fill3 = color === 'red' ? '#EF4444' : '#4CAF50';
  return '<svg width="' + size + '" height="' + Math.round(size * 1.2) + '" viewBox="0 0 100 120" style="display:inline-block">'
    + '<path d="M50 5 L90 22 C90 58 74 80 50 95 C26 80 10 58 10 22 Z" fill="' + fill1 + '" stroke="' + stroke1 + '" stroke-width="3"/>'
    + '<path d="M50 14 L82 28 C82 58 69 76 50 88 C31 76 18 58 18 28 Z" fill="' + fill2 + '"/>'
    + '<path d="M50 24 L73 35 C73 56 64 70 50 79 C36 70 27 56 27 35 Z" fill="' + fill3 + '"/>'
    + '</svg>';
}

function ensureGreenShieldStyle() {
  if (document.getElementById('crocbox-gs-blended-style')) return;
  var s = document.createElement('style');
  s.id = 'crocbox-gs-blended-style';
  s.textContent = [
    '#crocbox-consent-overlay { position:fixed; top:0; right:0; bottom:0; width:380px; z-index:999999;',
    '  background:#1E293B; border-left:2px solid #334155; font-family:-apple-system,BlinkMacSystemFont,sans-serif;',
    '  color:#F8FAFC; display:flex; flex-direction:column; overflow-y:auto; transition:border-color 0.3s; }',
    '#crocbox-consent-overlay.gs-asking { border-left-color:#10B981; box-shadow:-4px 0 20px rgba(16,185,129,0.15); }',
    '#crocbox-consent-overlay .gs-header { padding:20px 24px 16px; display:flex; align-items:center; gap:8px; }',
    '#crocbox-consent-overlay .gs-title { font-size:16px; font-weight:600; color:#F8FAFC; }',
    '#crocbox-consent-overlay .gs-body { flex:1; padding:0 24px 16px; display:flex; flex-direction:column; }',
    '#crocbox-consent-overlay .gs-label { font-size:11px; color:#94A3B8; margin-bottom:2px; }',
    '#crocbox-consent-overlay .gs-value { font-size:14px; color:#F8FAFC; word-break:break-word; margin-bottom:12px; }',
    '#crocbox-consent-overlay .gs-intent { font-size:14px; color:#F8FAFC; line-height:1.6; margin-bottom:12px; }',
    '#crocbox-consent-overlay .gs-private-note { font-size:12px; color:#94A3B8; line-height:1.6;',
    '  border-left:2px solid #10B981; padding-left:12px; margin-bottom:12px; }',
    '#crocbox-consent-overlay .gs-scope-toggle { font-size:12px; color:#94A3B8; cursor:pointer;',
    '  margin-bottom:8px; display:flex; align-items:center; gap:4px; }',
    '#crocbox-consent-overlay .gs-scope-toggle:hover { color:#F8FAFC; }',
    '#crocbox-consent-overlay .gs-scope-list { font-size:12px; margin-bottom:12px; }',
    '#crocbox-consent-overlay .gs-scope-list dt { color:#64748B; margin-top:6px; }',
    '#crocbox-consent-overlay .gs-scope-list dd { color:#F8FAFC; margin:0; word-break:break-all; }',
    '#crocbox-consent-overlay .gs-progress-bar { width:100%; height:4px; background:#0F172A;',
    '  border-radius:2px; overflow:hidden; margin:12px 0; }',
    '#crocbox-consent-overlay .gs-progress-fill { height:100%; background:#10B981; transition:width 1s linear; }',
    '#crocbox-consent-overlay .gs-btn-row { display:flex; gap:12px; margin-top:auto; padding-top:16px; }',
    '#crocbox-consent-overlay .gs-btn { flex:1; padding:14px 16px; border:none; border-radius:8px;',
    '  font-size:15px; font-weight:600; cursor:pointer; transition:background 0.2s; }',
    '#crocbox-consent-overlay .gs-btn-allow { background:#10B981; color:#0F172A; }',
    '#crocbox-consent-overlay .gs-btn-allow:hover { background:#059669; }',
    '#crocbox-consent-overlay .gs-btn-deny { background:#EF4444; color:#fff; }',
    '#crocbox-consent-overlay .gs-btn-deny:hover { background:#DC2626; }',
    '#crocbox-consent-overlay .gs-btn-dismiss { background:#0F172A; color:#F8FAFC; border:1px solid #334155; }',
    '#crocbox-consent-overlay .gs-btn-dismiss:hover { background:#334155; }',
    '#crocbox-consent-overlay .gs-choices { display:flex; flex-direction:column; gap:8px; margin-top:auto; padding-top:16px; }',
    '#crocbox-consent-overlay .gs-btn-rule { width:100%; padding:12px 16px; border:none; border-radius:8px;',
    '  font-size:14px; font-weight:500; cursor:pointer; transition:background 0.2s; text-align:left; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-allow-once { background:#10B981; color:#0F172A; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-allow-once:hover { background:#059669; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-allow-standing { background:#065F46; color:#F8FAFC; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-allow-standing:hover { background:#047857; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-time-limit { background:#1E3A5F; color:#F8FAFC; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-time-limit:hover { background:#1E4A7F; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-deny-once { background:#7F1D1D; color:#F8FAFC; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-deny-once:hover { background:#991B1B; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-deny-standing { background:#EF4444; color:#fff; }',
    '#crocbox-consent-overlay .gs-btn-rule.gs-deny-standing:hover { background:#DC2626; }',
    '#crocbox-consent-overlay .gs-accept-notice { font-size:12px; color:#F8FAFC; line-height:1.6;',
    '  background:#0F172A; border:1px solid #334155; border-radius:8px; padding:12px 16px; margin-top:12px; }',
    '#crocbox-consent-overlay .gs-accept-confirm-row { display:flex; gap:12px; margin-top:12px; }',
    '#crocbox-consent-overlay .gs-duration-picker { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; margin-bottom:8px; }',
    '#crocbox-consent-overlay .gs-duration-opt { padding:8px 12px; border:1px solid #334155; border-radius:6px;',
    '  background:#0F172A; color:#F8FAFC; font-size:13px; cursor:pointer; }',
    '#crocbox-consent-overlay .gs-duration-opt:hover { border-color:#10B981; }',
    '#crocbox-consent-overlay .gs-duration-opt.gs-selected { border-color:#10B981; background:#065F46; }',
    '#crocbox-consent-overlay .gs-rule-status { font-size:12px; margin-top:8px; padding:8px 12px;',
    '  border-radius:6px; }',
    '#crocbox-rules-panel { position:fixed; top:38px; left:50%; transform:translateX(-50%);',
    '  z-index:999998; background:#1E293B; border:1px solid #334155; border-radius:8px;',
    '  max-width:520px; width:90%; max-height:70vh; overflow-y:auto; display:none;',
    '  box-shadow:0 8px 32px rgba(0,0,0,0.5); font-family:-apple-system,sans-serif; color:#F8FAFC; }',
    '#crocbox-rules-panel .rp-header { padding:16px 20px 12px; border-bottom:1px solid #334155;',
    '  display:flex; align-items:center; justify-content:space-between; }',
    '#crocbox-rules-panel .rp-title { font-size:15px; font-weight:600; }',
    '#crocbox-rules-panel .rp-close { font-size:12px; color:#94A3B8; cursor:pointer; }',
    '#crocbox-rules-panel .rp-close:hover { color:#F8FAFC; }',
    '#crocbox-rules-panel .rp-body { padding:12px 20px 16px; }',
    '#crocbox-rules-panel .rp-rule { padding:12px 0; border-bottom:1px solid #0F172A; }',
    '#crocbox-rules-panel .rp-rule:last-child { border-bottom:none; }',
    '#crocbox-rules-panel .rp-sentence { font-size:14px; color:#F8FAFC; line-height:1.5; }',
    '#crocbox-rules-panel .rp-meta { font-size:11px; color:#94A3B8; margin-top:4px; }',
    '#crocbox-rules-panel .rp-revoke { margin-top:8px; padding:6px 14px; border:1px solid #EF4444;',
    '  border-radius:6px; background:transparent; color:#EF4444; font-size:12px;',
    '  cursor:pointer; font-weight:500; }',
    '#crocbox-rules-panel .rp-revoke:hover { background:#7F1D1D; color:#F8FAFC; }',
    '#crocbox-rules-panel .rp-empty { font-size:13px; color:#94A3B8; text-align:center; padding:24px 0; }',
    '#crocbox-rules-panel .rp-loading { font-size:13px; color:#94A3B8; text-align:center; padding:24px 0; }',
    '#crocbox-rules-panel .rp-error { font-size:13px; color:#F59E0B; text-align:center; padding:24px 0; }',
    '#crocbox-consent-overlay .gs-center { flex:1; display:flex; flex-direction:column;',
    '  align-items:center; justify-content:center; text-align:center; }',
    '#crocbox-consent-overlay .gs-entity-type { font-size:11px; color:#64748B;',
    '  text-transform:uppercase; letter-spacing:0.5px; margin-top:2px; }',
    '#crocbox-consent-overlay .gs-receipt-hash { font-size:11px; color:#94A3B8;',
    '  margin-top:8px; word-break:break-all; font-family:monospace; }',
    '#crocbox-consent-overlay .gs-receipt-readable { }',
  ].join('\n');
  document.head.appendChild(s);
}

function renderGreenShieldPanel() {
  ensureGreenShieldStyle();
  var old = document.getElementById('crocbox-consent-overlay');
  if (old) old.remove();

  var overlay = document.createElement('div');
  overlay.id = 'crocbox-consent-overlay';

  if (gsState.current === 'asking' && gsState.pending) {
    overlay.className = 'gs-asking';
    var p = gsState.pending;
    var agentName = p.entity_name || 'Your AI';
    var intentLine = p.summary_text || p.summary || '';
    if (!intentLine && (p.action_type || p.target)) {
      intentLine = [p.action_type, p.target].filter(Boolean).join(' \u00B7 ');
    }
    var isWebSearch = (p.action_type || p.toolName) === 'web_search';

    // Header
    var header = document.createElement('div');
    header.className = 'gs-header';
    header.innerHTML = getGreenShieldSVG(20, 'green') + '<span class="gs-title">Green Shield</span>';
    overlay.appendChild(header);

    // Body
    var body = document.createElement('div');
    body.className = 'gs-body';

    // Agent name + type
    var nameEl = document.createElement('div');
    nameEl.innerHTML = '<div style="font-size:14px;font-weight:500;color:#F8FAFC">' + escapeHtml(agentName) + ' wants your permission:</div>';
    if (p.entity_type) {
      nameEl.innerHTML += '<div class="gs-entity-type">' + escapeHtml(p.entity_type) + '</div>';
    }
    body.appendChild(nameEl);

    // Intent line
    if (intentLine) {
      var intentDiv = document.createElement('div');
      intentDiv.style.marginTop = '12px';
      intentDiv.innerHTML = '<div class="gs-label">Here\'s what I\'ll do:</div>'
        + '<div class="gs-intent">' + escapeHtml(intentLine) + '</div>';
      body.appendChild(intentDiv);
    }

    // Private search note
    if (isWebSearch) {
      var noteDiv = document.createElement('div');
      noteDiv.className = 'gs-private-note';
      noteDiv.textContent = 'Private search. This runs through your own trusted server \u2014 no account, no profile, nothing kept or used for training. Results come from public search engines, queried anonymously.';
      body.appendChild(noteDiv);
    }

    // Action type
    if (p.action_type || p.toolName) {
      var actionDiv = document.createElement('div');
      actionDiv.innerHTML = '<div class="gs-label">What it\'s asking to do</div>'
        + '<div class="gs-value">' + escapeHtml(p.action_type || p.toolName) + '</div>';
      body.appendChild(actionDiv);
    }

    // Target
    if (p.target || p.toolDetail) {
      var targetDiv = document.createElement('div');
      targetDiv.innerHTML = '<div class="gs-label">What it touches</div>'
        + '<div class="gs-value">' + escapeHtml(p.target || p.toolDetail) + '</div>';
      body.appendChild(targetDiv);
    }

    // Countdown
    var countdownDiv = document.createElement('div');
    countdownDiv.innerHTML = '<div class="gs-label">The window</div>'
      + '<div class="gs-value" id="gs-countdown-text">Expires in ' + gsState.countdown + 's</div>';
    body.appendChild(countdownDiv);

    // Progress bar
    var progressOuter = document.createElement('div');
    progressOuter.className = 'gs-progress-bar';
    var progressInner = document.createElement('div');
    progressInner.className = 'gs-progress-fill';
    progressInner.id = 'gs-progress-fill';
    progressInner.style.width = (gsState.countdown / GS_COUNTDOWN_SECONDS * 100) + '%';
    progressOuter.appendChild(progressInner);
    body.appendChild(progressOuter);

    // Scope toggle
    var scopeRows = [];
    if (p.entity_name) scopeRows.push(['Assistant', p.entity_name]);
    if (p.entity_type) scopeRows.push(['Type', p.entity_type]);
    if (p.action_type || p.toolName) scopeRows.push(['Action', p.action_type || p.toolName]);
    if (p.target || p.toolDetail) scopeRows.push(['Target', p.target || p.toolDetail]);
    if (p.source_product) scopeRows.push(['Source', p.source_product]);
    if (p.session_id) scopeRows.push(['Session', p.session_id]);

    if (scopeRows.length > 0) {
      var scopeToggle = document.createElement('div');
      scopeToggle.className = 'gs-scope-toggle';
      scopeToggle.innerHTML = '<span id="gs-scope-arrow">' + (gsState.scopeOpen ? '\u25B2' : '\u25BC') + '</span> See exact scope';
      scopeToggle.addEventListener('click', function() {
        gsState.scopeOpen = !gsState.scopeOpen;
        var list = document.getElementById('gs-scope-list');
        var arrow = document.getElementById('gs-scope-arrow');
        if (list) list.style.display = gsState.scopeOpen ? 'block' : 'none';
        if (arrow) arrow.textContent = gsState.scopeOpen ? '\u25B2' : '\u25BC';
      });
      body.appendChild(scopeToggle);

      var scopeList = document.createElement('dl');
      scopeList.className = 'gs-scope-list';
      scopeList.id = 'gs-scope-list';
      scopeList.style.display = gsState.scopeOpen ? 'block' : 'none';
      scopeRows.forEach(function(pair) {
        scopeList.innerHTML += '<dt>' + escapeHtml(pair[0]) + '</dt><dd>' + escapeHtml(pair[1]) + '</dd>';
      });
      body.appendChild(scopeList);
    }

    // Five choices
    var choicesDiv = document.createElement('div');
    choicesDiv.className = 'gs-choices';
    choicesDiv.id = 'gs-choices-container';

    var actionLabel = escapeHtml(p.action_type || p.toolName || 'this action');
    var agentLabel = escapeHtml(agentName);

    var choices = [
      { label: 'Allow once', cls: 'gs-allow-once', decision: 'allow', rule: false },
      { label: 'Allow until I change it', cls: 'gs-allow-standing', decision: 'allow', rule: 'standing' },
      { label: 'Set a time limit', cls: 'gs-time-limit', decision: 'allow', rule: 'timed' },
      { label: 'No', cls: 'gs-deny-once', decision: 'deny', rule: false },
      { label: 'Never allow this', cls: 'gs-deny-standing', decision: 'deny', rule: 'deny-standing' }
    ];

    choices.forEach(function(ch) {
      var btn = document.createElement('button');
      btn.className = 'gs-btn-rule ' + ch.cls;
      btn.textContent = ch.label;
      btn.addEventListener('click', function() {
        if (!ch.rule) {
          handleDecision(ch.decision);
          return;
        }
        showAcceptNotice(ch, actionLabel, agentLabel);
      });
      choicesDiv.appendChild(btn);
    });

    body.appendChild(choicesDiv);

    overlay.appendChild(body);

  } else if (gsState.current === 'receipt' && gsState.receipt) {
    var r = gsState.receipt;
    var isAllow = r.decision === 'allow';
    var shieldColor = isAllow ? 'green' : 'red';

    var header2 = document.createElement('div');
    header2.className = 'gs-header';
    header2.innerHTML = getGreenShieldSVG(20, shieldColor) + '<span class="gs-title">Green Shield</span>';
    overlay.appendChild(header2);

    var body2 = document.createElement('div');
    body2.className = 'gs-body';

    var center = document.createElement('div');
    center.className = 'gs-center';
    center.innerHTML = getGreenShieldSVG(40, shieldColor);

    var subject = [r.action_type, r.target].filter(Boolean).join(' on ');

    if (isAllow) {
      center.innerHTML += '<div style="font-size:14px;font-weight:500;margin-top:12px">Allowed' + (subject ? ' \u2014 ' + escapeHtml(subject) + '.' : '.') + '</div>';
      if (r.action_type === 'web_search') {
        center.innerHTML += '<div style="font-size:12px;color:#CBD5E1;margin-top:8px">Search ran privately \u2014 nothing kept.</div>';
      }
    } else {
      center.innerHTML += '<div style="font-size:14px;font-weight:500;margin-top:12px">Stopped \u2014 you said No.</div>';
      if (subject) {
        center.innerHTML += '<div style="font-size:12px;color:#CBD5E1;margin-top:8px;word-break:break-word">' + escapeHtml(subject) + '</div>';
      }
    }

    // Step 5: when a standing rule answered, say which one and why nobody asked.
    if (r.rule_sentence) {
      center.innerHTML += '<div style="font-size:12px;color:#10B981;margin-top:10px">Your rule: \u201C'
        + escapeHtml(r.rule_sentence) + '\u201D</div>'
        + '<div style="font-size:11px;color:#CBD5E1;margin-top:4px">You were not asked because you set this rule.</div>';
    }

    // RE-1: three honest states. Hash present, hash absent, or still waiting.
    if (r.audit_hash) {
      center.innerHTML += '<div style="font-size:12px;color:#CBD5E1;margin-top:12px">Recorded in Activity</div>'
        + '<div class="gs-receipt-hash">' + escapeHtml(r.audit_hash) + '</div>';
    } else if (r.recorded === false) {
      center.innerHTML += '<div style="font-size:12px;color:#F59E0B;margin-top:12px;font-weight:600">\u26A0 Decision made but NOT recorded</div>'
        + '<div style="font-size:11px;color:#F59E0B;margin-top:4px;line-height:1.4">This action is not in your Activity log. Contact support.</div>';
    } else if (r.recorded === null) {
      center.innerHTML += '<div style="font-size:12px;color:#94A3B8;margin-top:12px">Recording\u2026</div>';
    }

    body2.appendChild(center);

    var btnRow2 = document.createElement('div');
    btnRow2.className = 'gs-btn-row';
    var dismissBtn = document.createElement('button');
    dismissBtn.className = 'gs-btn gs-btn-dismiss';
    dismissBtn.textContent = 'Dismiss';
    dismissBtn.addEventListener('click', function() {
      gsState.current = 'guarded';
      gsState.receipt = null;
      renderGreenShieldPanel();
    });
    btnRow2.appendChild(dismissBtn);
    body2.appendChild(btnRow2);

    overlay.appendChild(body2);

  } else {
    // Guarded state
    var header3 = document.createElement('div');
    header3.className = 'gs-header';
    header3.innerHTML = getGreenShieldSVG(20, 'green') + '<span class="gs-title">Green Shield</span>';
    overlay.appendChild(header3);

    var body3 = document.createElement('div');
    body3.className = 'gs-body';

    var center3 = document.createElement('div');
    center3.className = 'gs-center';
    center3.innerHTML = getGreenShieldSVG(48, 'green')
      + '<div style="font-size:14px;font-weight:500;margin-top:16px">Guarded</div>'
      + '<div style="font-size:13px;color:#F8FAFC;margin-top:8px;max-width:260px;line-height:1.6">Your assistant is working inside your rules. Nothing needs you right now.</div>'
      + '<div style="font-size:12px;color:#94A3B8;margin-top:12px;line-height:1.6">When your AI needs permission, the request will appear here.</div>';
    body3.appendChild(center3);
    overlay.appendChild(body3);
  }

  if (document.body) {
    document.body.appendChild(overlay);
  }
}

// S3: duration options for time-limited rules
var GS_DURATION_OPTIONS = [
  { label: '1 hour', seconds: 3600 },
  { label: '4 hours', seconds: 14400 },
  { label: '1 day', seconds: 86400 },
  { label: '1 week', seconds: 604800 },
  { label: '30 days', seconds: 2592000 }
];

function showAcceptNotice(choice, actionLabel, agentLabel) {
  var container = document.getElementById('gs-choices-container');
  if (!container) return;

  // Clear existing choices
  container.innerHTML = '';

  var noticeDiv = document.createElement('div');
  noticeDiv.className = 'gs-accept-notice';

  var selectedDuration = { seconds: null };

  if (choice.rule === 'timed') {
    // Duration picker first
    var pickerLabel = document.createElement('div');
    pickerLabel.style.cssText = 'font-size:13px;font-weight:500;margin-bottom:8px;';
    pickerLabel.textContent = 'How long?';
    noticeDiv.appendChild(pickerLabel);

    var pickerDiv = document.createElement('div');
    pickerDiv.className = 'gs-duration-picker';
    GS_DURATION_OPTIONS.forEach(function(opt) {
      var optBtn = document.createElement('button');
      optBtn.className = 'gs-duration-opt';
      optBtn.textContent = opt.label;
      optBtn.addEventListener('click', function() {
        selectedDuration.seconds = opt.seconds;
        var allOpts = pickerDiv.querySelectorAll('.gs-duration-opt');
        allOpts.forEach(function(o) { o.className = 'gs-duration-opt'; });
        optBtn.className = 'gs-duration-opt gs-selected';
        // Show the accept notice text after selection
        if (!document.getElementById('gs-accept-text')) {
          var acceptText = document.createElement('div');
          acceptText.id = 'gs-accept-text';
          acceptText.style.cssText = 'margin-top:12px;line-height:1.6;';
          acceptText.textContent = 'We\u2019ll let ' + agentLabel + ' ' + actionLabel
            + ' without asking you for ' + opt.label + '.';
          noticeDiv.appendChild(acceptText);
        } else {
          document.getElementById('gs-accept-text').textContent =
            'We\u2019ll let ' + agentLabel + ' ' + actionLabel
            + ' without asking you for ' + opt.label + '.';
        }
      });
      pickerDiv.appendChild(optBtn);
    });
    noticeDiv.appendChild(pickerDiv);
  } else {
    // Accept notice text for standing rules
    var noticeText = document.createElement('div');
    noticeText.style.cssText = 'line-height:1.6;';
    if (choice.rule === 'standing') {
      noticeText.textContent = 'We\u2019ll let ' + agentLabel + ' ' + actionLabel
        + ' without asking you. Opn.li allows this as a convenience \u2014 we\u2019ll check in each quarter to make sure you still want it.';
    } else if (choice.rule === 'deny-standing') {
      noticeText.textContent = agentLabel + ' will never be allowed to ' + actionLabel
        + '. You can change this anytime in your rules.';
    }
    noticeDiv.appendChild(noticeText);
  }

  container.appendChild(noticeDiv);

  // Confirm / Go back buttons
  var confirmRow = document.createElement('div');
  confirmRow.className = 'gs-accept-confirm-row';

  var backBtn = document.createElement('button');
  backBtn.className = 'gs-btn gs-btn-dismiss';
  backBtn.style.flex = '1';
  backBtn.textContent = 'Go back';
  backBtn.addEventListener('click', function() {
    renderGreenShieldPanel();
  });

  var confirmBtn = document.createElement('button');
  confirmBtn.className = 'gs-btn ' + (choice.decision === 'allow' ? 'gs-btn-allow' : 'gs-btn-deny');
  confirmBtn.style.flex = '1';
  confirmBtn.textContent = 'Confirm';
  confirmBtn.addEventListener('click', function() {
    if (choice.rule === 'timed' && !selectedDuration.seconds) {
      // Flash the picker to indicate selection needed
      var picker = container.querySelector('.gs-duration-picker');
      if (picker) {
        picker.style.border = '1px solid #EF4444';
        picker.style.borderRadius = '8px';
        picker.style.padding = '4px';
        setTimeout(function() {
          picker.style.border = 'none';
          picker.style.padding = '0';
        }, 1500);
      }
      return;
    }
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Creating rule...';

    // Build expires_at for timed rules
    var expiresAt = null;
    if (choice.rule === 'timed' && selectedDuration.seconds) {
      expiresAt = new Date(Date.now() + selectedDuration.seconds * 1000).toISOString();
    }

    // Build the rule sentence — exactly what the NHB was shown
    var ruleSentence = '';
    if (choice.rule === 'standing') {
      ruleSentence = 'Allow ' + agentLabel + ' to ' + actionLabel + ' without asking me';
    } else if (choice.rule === 'deny-standing') {
      ruleSentence = 'Never allow ' + agentLabel + ' to ' + actionLabel;
    } else if (choice.rule === 'timed') {
      var durLabel = '';
      GS_DURATION_OPTIONS.forEach(function(o) {
        if (o.seconds === selectedDuration.seconds) durLabel = o.label;
      });
      ruleSentence = 'Allow ' + agentLabel + ' to ' + actionLabel + ' without asking me for ' + durLabel;
    }

    var actionType = gsState.pending ? (gsState.pending.action_type || gsState.pending.toolName) : actionLabel;

    ipcRenderer.invoke('crocbox:create-rule', {
      action_type: actionType,
      decision: choice.decision,
      rule_sentence: ruleSentence,
      expires_at: expiresAt
    }).then(function(result) {
      if (result && result.ok) {
        // Rule created — now resolve the consent decision
        handleDecision(choice.decision);
      } else {
        // Rule creation failed — show error, let NHB decide what to do
        var statusDiv = document.createElement('div');
        statusDiv.className = 'gs-rule-status';
        statusDiv.style.cssText = 'color:#F59E0B;background:#1C1917;border:1px solid #F59E0B;';
        statusDiv.textContent = 'Rule was NOT created'
          + (result && result.error ? ': ' + result.error : '')
          + '. Your choice still counts for this one action.';
        container.appendChild(statusDiv);

        // Re-enable as a one-time decision
        confirmBtn.textContent = (choice.decision === 'allow' ? 'Allow once instead' : 'Block once instead');
        confirmBtn.disabled = false;
        confirmBtn.addEventListener('click', function() {
          handleDecision(choice.decision);
        }, { once: true });
      }
    }).catch(function(err) {
      confirmBtn.textContent = (choice.decision === 'allow' ? 'Allow once instead' : 'Block once instead');
      confirmBtn.disabled = false;
      var statusDiv = document.createElement('div');
      statusDiv.className = 'gs-rule-status';
      statusDiv.style.cssText = 'color:#F59E0B;background:#1C1917;border:1px solid #F59E0B;';
      statusDiv.textContent = 'Could not reach the consent server. Your choice still counts for this one action.';
      container.appendChild(statusDiv);
      confirmBtn.addEventListener('click', function() {
        handleDecision(choice.decision);
      }, { once: true });
    });
  });

  confirmRow.appendChild(backBtn);
  confirmRow.appendChild(confirmBtn);
  container.appendChild(confirmRow);
}

function handleDecision(decision) {
  if (!gsState.pending) return;
  var requestId = gsState.pending.requestId;
  var p = gsState.pending;

  // Build detail string for target
  var toolDetail = '';
  if (p.toolParams && typeof p.toolParams === 'object') {
    if (p.toolParams.command) toolDetail = p.toolParams.command;
    else if (p.toolParams.path || p.toolParams.filePath) toolDetail = p.toolParams.path || p.toolParams.filePath;
    else if (p.toolParams.query) toolDetail = p.toolParams.query;
    else if (p.toolParams.url) toolDetail = p.toolParams.url;
    else if (p.toolParams.content) toolDetail = (p.toolParams.content + '').substring(0, 80);
  }

  console.log('[CROCbox] Green Shield: User clicked ' + decision.toUpperCase());

  // Stop countdown
  if (gsState.countdownTimer) {
    clearInterval(gsState.countdownTimer);
    gsState.countdownTimer = null;
  }

  // Set receipt
  gsState.current = 'receipt';
  gsState.receipt = {
    requestId: requestId,
    decision: decision,
    entity_name: p.entity_name,
    action_type: p.action_type || p.toolName,
    target: p.target || toolDetail,
    audit_hash: null,
    recorded: null
  };
  gsState.pending = null;
  gsState.scopeOpen = false;

  renderGreenShieldPanel();

  // Send decision to main process
  ipcRenderer.invoke('crocbox:green-consent-resolve', requestId, decision);
}

function escapeHtml(str) {
  if (!str) return '';
  return (str + '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Green Shield consent request handler
ipcRenderer.on('crocbox:green-consent-request', function(_event, data) {
  var requestId = data.requestId;
  var toolName = data.toolName || 'unknown action';
  var toolParams = data.toolParams || {};
  console.log('[CROCbox Preload] Green Shield consent request: ' + toolName + ' id=' + requestId);

  // Build detail string
  var toolDetail = '';
  if (toolParams && typeof toolParams === 'object') {
    if (toolParams.command) toolDetail = toolParams.command;
    else if (toolParams.path || toolParams.filePath) toolDetail = toolParams.path || toolParams.filePath;
    else if (toolParams.query) toolDetail = toolParams.query;
    else if (toolParams.url) toolDetail = toolParams.url;
    else if (toolParams.content) toolDetail = (toolParams.content + '').substring(0, 80);
    else {
      var keys = Object.keys(toolParams).slice(0, 3);
      toolDetail = keys.map(function(k) { return k + ': ' + (toolParams[k] + '').substring(0, 40); }).join(', ');
    }
  }

  // Map tool name to action_type for display
  var actionType = toolName;
  if (toolName === 'exec' || toolName === 'Bash') actionType = 'exec';
  if (toolName === 'read' || toolName === 'Read') actionType = 'read';
  if (toolName === 'write' || toolName === 'Write') actionType = 'write';
  if (toolName === 'web_search') actionType = 'web_search';
  if (toolName === 'web_fetch') actionType = 'web_fetch';

  // Set pending state
  gsState.current = 'asking';
  gsState.pending = {
    requestId: requestId,
    toolName: toolName,
    toolParams: toolParams,
    toolDetail: toolDetail,
    action_type: data.action_type || actionType,
    target: data.target || toolDetail,
    entity_name: data.entity_name || 'CROCbox',
    entity_type: data.entity_type || 'ai_agent',
    source_product: data.source_product || 'crocbox',
    session_id: data.session_id || '',
    summary_text: data.summary_text || ''
  };
  gsState.countdown = GS_COUNTDOWN_SECONDS;
  gsState.scopeOpen = false;
  gsState.receipt = null;

  // Start countdown
  if (gsState.countdownTimer) clearInterval(gsState.countdownTimer);
  gsState.countdownTimer = setInterval(function() {
    gsState.countdown--;
    var textEl = document.getElementById('gs-countdown-text');
    if (textEl) textEl.textContent = 'Expires in ' + gsState.countdown + 's';
    var fillEl = document.getElementById('gs-progress-fill');
    if (fillEl) fillEl.style.width = (gsState.countdown / GS_COUNTDOWN_SECONDS * 100) + '%';
    if (gsState.countdown <= 0) {
      clearInterval(gsState.countdownTimer);
      gsState.countdownTimer = null;
    }
  }, 1000);

  // Render
  if (document.body) {
    renderGreenShieldPanel();
  } else {
    document.addEventListener('DOMContentLoaded', function() { renderGreenShieldPanel(); });
  }
});

// Green Shield Timeout — transition to blocked receipt
ipcRenderer.on('crocbox:green-consent-timeout', function(_event, data) {
  var requestId = data.requestId;
  console.log('[CROCbox Preload] Green Shield timeout received: id=' + requestId);

  if (gsState.countdownTimer) {
    clearInterval(gsState.countdownTimer);
    gsState.countdownTimer = null;
  }

  if (gsState.current === 'asking' && gsState.pending && gsState.pending.requestId === requestId) {
    gsState.current = 'receipt';
    gsState.receipt = {
      decision: 'deny',
      entity_name: gsState.pending.entity_name,
      action_type: gsState.pending.action_type || gsState.pending.toolName,
      target: gsState.pending.target || gsState.pending.toolDetail,
      audit_hash: null
    };
    gsState.pending = null;
    renderGreenShieldPanel();

    // Auto-dismiss after 12 seconds — a receipt nobody can read is not a receipt
    setTimeout(function() {
      if (gsState.current === 'receipt') {
        gsState.current = 'guarded';
        gsState.receipt = null;
        renderGreenShieldPanel();
      }
    }, 12000);
  }
});

// Step 5: a standing rule already decided — render the receipt, never the question.
ipcRenderer.on('crocbox:green-consent-rule-applied', function(_event, data) {
  console.log('[CROCbox Preload] Green Shield rule applied: id=' + (data && data.requestId) +
              ' decision=' + (data && data.decision) + ' recorded=' + (data && data.recorded));
  if (!data) return;

  if (gsState.countdownTimer) {
    clearInterval(gsState.countdownTimer);
    gsState.countdownTimer = null;
  }

  var p = data.toolParams || {};
  var detail = p.query || p.url || p.path || p.filePath ||
               (p.command ? p.command : null) ||
               (p.content ? (p.content + '').substring(0, 80) : null);

  gsState.current = 'receipt';
  gsState.pending = null;
  gsState.scopeOpen = false;
  gsState.receipt = {
    requestId: data.requestId,
    decision: data.decision,
    entity_name: 'CROCbox',
    action_type: data.toolName,
    target: detail,
    rule_sentence: data.rule_sentence || null,
    audit_hash: data.audit_hash || null,
    recorded: !!data.recorded
  };
  renderGreenShieldPanel();
});

// RE-1: Green Shield chain receipt — fill in the hash, or say it was not recorded
ipcRenderer.on('crocbox:green-consent-receipt', function(_event, data) {
  var requestId = data && data.requestId;
  console.log('[CROCbox Preload] Green Shield receipt: id=' + requestId + ' recorded=' + (data && data.recorded));

  // The NHB may have already dismissed the panel, or moved on to another decision.
  // Only update the receipt this answer belongs to.
  if (gsState.current !== 'receipt' || !gsState.receipt) return;
  if (gsState.receipt.requestId !== requestId) return;

  gsState.receipt.audit_hash = (data && data.audit_hash) || null;
  gsState.receipt.recorded = !!(data && data.recorded);
  renderGreenShieldPanel();
});

// Render Guarded state on page load
function initGreenShieldGuarded() {
  if (document.body) {
    renderGreenShieldPanel();
  } else {
    document.addEventListener('DOMContentLoaded', function() { renderGreenShieldPanel(); });
  }
}
// Delay initial render so the OpenClaw UI loads first
setTimeout(initGreenShieldGuarded, 3000);

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
        { id: 'ctrl-my-rules', icon: '\uD83D\uDCDC', label: 'My Rules', ipc: 'crocbox:open-my-rules' },
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

// ── Review Rules Panel ──────────────────────────────────────────
function ensureRulesPanel() {
  if (document.getElementById('crocbox-rules-panel')) return;
  var panel = document.createElement('div');
  panel.id = 'crocbox-rules-panel';
  panel.innerHTML = '<div class="rp-header"><span class="rp-title">My Rules</span>'
    + '<span class="rp-close" id="rp-close-btn">Close</span></div>'
    + '<div class="rp-body" id="rp-body"><div class="rp-loading">Loading rules...</div></div>';
  document.body.appendChild(panel);
  document.getElementById('rp-close-btn').addEventListener('click', function() {
    panel.style.display = 'none';
  });
  document.addEventListener('click', function(ev) {
    if (panel.style.display !== 'none' && !panel.contains(ev.target)) {
      var ctrl = document.getElementById('crocbox-bar-controls');
      if (!ctrl || !ctrl.contains(ev.target)) {
        panel.style.display = 'none';
      }
    }
  });
}

function showRulesPanel() {
  ensureGreenShieldStyle();
  ensureRulesPanel();
  var panel = document.getElementById('crocbox-rules-panel');
  var body = document.getElementById('rp-body');
  panel.style.display = 'block';
  body.innerHTML = '<div class="rp-loading">Loading rules...</div>';

  // Close other panels
  var cp = document.getElementById('crocbox-controls-panel');
  if (cp) cp.style.display = 'none';
  var sd = document.getElementById('crocbox-shield-detail');
  if (sd) sd.style.display = 'none';

  ipcRenderer.invoke('crocbox:list-rules').then(function(result) {
    if (!result || !result.ok) {
      body.innerHTML = '<div class="rp-error">Could not load rules'
        + (result && result.error ? ': ' + escapeHtml(result.error) : '') + '</div>';
      return;
    }
    var rules = result.rules || [];
    if (rules.length === 0) {
      body.innerHTML = '<div class="rp-empty">No active rules. When you choose '
        + '&ldquo;Allow until I change it&rdquo; or &ldquo;Never allow this&rdquo; '
        + 'on the Green Shield card, your rules will appear here.</div>';
      return;
    }
    body.innerHTML = '';
    rules.forEach(function(r) {
      var ruleDiv = document.createElement('div');
      ruleDiv.className = 'rp-rule';
      ruleDiv.id = 'rp-rule-' + r.rule_id;

      var sentence = document.createElement('div');
      sentence.className = 'rp-sentence';
      var icon = r.decision === 'allow' ? '\u2705 ' : '\u26D4 ';
      sentence.textContent = icon + (r.rule_sentence || r.action_type);
      ruleDiv.appendChild(sentence);

      var meta = document.createElement('div');
      meta.className = 'rp-meta';
      var parts = [];
      if (r.source_product) parts.push(r.source_product);
      if (r.action_type) parts.push(r.action_type);
      if (r.expires_at) {
        var exp = new Date(r.expires_at);
        parts.push('expires ' + exp.toLocaleDateString());
      }
      var created = new Date(r.created_at);
      parts.push('set ' + created.toLocaleDateString());
      meta.textContent = parts.join(' \u00B7 ');
      ruleDiv.appendChild(meta);

      var revokeBtn = document.createElement('button');
      revokeBtn.className = 'rp-revoke';
      revokeBtn.textContent = 'Revoke';
      revokeBtn.addEventListener('click', function() {
        // Hide the revoke button, show confirmation
        revokeBtn.style.display = 'none';

        var confirmArea = document.createElement('div');
        confirmArea.style.cssText = 'margin-top:8px;';

        var notice = document.createElement('div');
        notice.style.cssText = 'font-size:12px;color:#CBD5E1;line-height:1.5;margin-bottom:8px;'
          + 'background:#0F172A;border:1px solid #334155;border-radius:6px;padding:8px 12px;';
        notice.textContent = 'This rule will be removed. Your AI will ask permission for '
          + (r.action_type || 'this action') + ' again.';
        confirmArea.appendChild(notice);

        var btnRow = document.createElement('div');
        btnRow.className = 'rp-confirm-row';
        btnRow.style.cssText = 'display:flex;gap:8px;';

        var backBtn = document.createElement('button');
        backBtn.style.cssText = 'flex:1;padding:6px 12px;border:1px solid #334155;border-radius:6px;'
          + 'background:transparent;color:#F8FAFC;font-size:12px;cursor:pointer;';
        backBtn.textContent = 'Go back';
        backBtn.addEventListener('click', function() {
          confirmArea.remove();
          revokeBtn.style.display = '';
        });

        var confirmBtn = document.createElement('button');
        confirmBtn.style.cssText = 'flex:1;padding:6px 12px;border:1px solid #EF4444;border-radius:6px;'
          + 'background:#7F1D1D;color:#F8FAFC;font-size:12px;cursor:pointer;font-weight:500;';
        confirmBtn.textContent = 'Confirm';
        confirmBtn.addEventListener('click', function() {
          confirmBtn.disabled = true;
          confirmBtn.textContent = 'Revoking...';
          backBtn.disabled = true;
          ipcRenderer.invoke('crocbox:revoke-rule', r.rule_id).then(function(res) {
            if (res && res.ok) {
              ruleDiv.style.opacity = '0.4';
              confirmArea.innerHTML = '<div style="font-size:12px;color:#94A3B8;margin-top:4px;">Revoked.</div>';
              setTimeout(function() {
                ruleDiv.remove();
                var remaining = document.querySelectorAll('.rp-rule');
                if (remaining.length === 0) {
                  var bd = document.getElementById('rp-body');
                  if (bd) bd.innerHTML = '<div class="rp-empty">All rules revoked. '
                    + 'Your AI will ask permission for every action.</div>';
                }
              }, 1500);
            } else {
              confirmBtn.disabled = false;
              confirmBtn.textContent = 'Failed \u2014 try again';
              confirmBtn.style.borderColor = '#F59E0B';
              backBtn.disabled = false;
            }
          }).catch(function() {
            confirmBtn.disabled = false;
            confirmBtn.textContent = 'Failed \u2014 try again';
            backBtn.disabled = false;
          });
        });

        btnRow.appendChild(backBtn);
        btnRow.appendChild(confirmBtn);
        confirmArea.appendChild(btnRow);
        ruleDiv.appendChild(confirmArea);
      });
      ruleDiv.appendChild(revokeBtn);

      body.appendChild(ruleDiv);
    });
  }).catch(function(err) {
    body.innerHTML = '<div class="rp-error">Error: ' + escapeHtml(err.message || 'unknown') + '</div>';
  });
}

ipcRenderer.on('crocbox:open-my-rules', function() {
  showRulesPanel();
});

// ── CROCbox Identity + IPC Bridge ──────────────────────────────
contextBridge.exposeInMainWorld('crocbox', {
  // Identity
  version: '1.0.0-beta.12',
  phase: 'soft-launch',
  isCROCbox: true,
  // Shield Scoring Engine — get detail HTML for click-through
  getShieldDetail: function() {
    return ipcRenderer.invoke('crocbox:shield-detail');
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
console.log('[CROCbox Preload] Preload script loaded (Blended Green Shield + Trust Bar IPC active)');
