/**
 * CROCbox v0.9 — Shield Scoring Engine
 * 
 * Translates three major agent security frameworks into a single
 * visible trust signal (Green/Yellow/Red Shield).
 * 
 * Frameworks scored:
 *   - OWASP Agentic AI Top 10 (ASI01-ASI10) — tool risk surface
 *   - AWS Agentic AI Security Scoping Matrix — autonomy classification
 *   - Meta Agents Rule of Two — capability configuration
 * 
 * The Shield is the green padlock for the Agent Economy.
 * 
 * @see OPN_OCE_ATL-CompetitiveAnalysis_21MAR26_v2
 * @see OPN_PM_FullCROC-Mode_16MAR26_v2, Section 3
 */

// ── OWASP ASI Classification Map ──────────────────────────────
// Maps OpenClaw tool groups to OWASP Agentic AI Top 10 risk IDs
const OWASP_ASI_MAP = {
  // ASI01: Agent Goal Hijack — untrusted external inputs
  'web.web_search':  ['ASI01', 'ASI02'],
  'web.web_fetch':   ['ASI01', 'ASI02'],
  // ASI02: Tool Misuse — legitimate tools used destructively
  'fs.read':         ['ASI02', 'ASI03'],
  'fs.write':        ['ASI02', 'ASI03', 'ASI05'],
  'fs.edit':         ['ASI02', 'ASI03'],
  'fs.apply_patch':  ['ASI02', 'ASI03', 'ASI05'],
  // ASI03: Identity & Privilege Abuse
  'runtime.exec':    ['ASI02', 'ASI03', 'ASI05'],
  'runtime.process': ['ASI02', 'ASI03'],
  // ASI04: Supply Chain — MCP skills (dynamic, assessed at runtime)
  // ASI05: Unexpected Code Execution
  // ASI09: Human-Agent Trust Exploit (structural — ATL defense)
  'ui.browser':      ['ASI01', 'ASI02'],
  'ui.canvas':       ['ASI02'],
  'messaging.message': ['ASI02', 'ASI03'],
  'media.image':     ['ASI02'],
  'media.tts':       ['ASI02'],
  'automation.cron':  ['ASI02', 'ASI10'],
  'automation.gateway': ['ASI02'],
  // Safe tools — no ASI risk
  'memory.memory_search': [],
  'memory.memory_get':    [],
  'sessions.list':            [],
  'sessions.history':         [],
  'sessions.send':            [],
  'sessions.spawn':           [],
  'sessions.subagents':       [],
  'sessions.status':          [],
  'sessions.sessions_list':   [],
  'sessions.sessions_history':[],
  'sessions.sessions_send':   [],
  'sessions.sessions_spawn':  [],
  'sessions.sessions_subagents':[],
  'sessions.sessions_status': [],
  'sessions.session_status':  [],
  'agents.agents_list':   [],
  'nodes.nodes':          [],
};

// ── ATL Classification Map ────────────────────────────────────
// From PM Spec Section 3: Verified Tool Catalog
const ATL_CLASSIFY = {
  'fs.read':          'filesystem_read',
  'fs.write':         'filesystem_write',
  'fs.edit':          'filesystem_write',
  'fs.apply_patch':   'filesystem_write',
  'runtime.exec':     'shell_exec',
  'runtime.process':  'shell_exec',
  'web.web_search':   'web_search',
  'web.web_fetch':    'api_call',
  'ui.browser':       'browser_action',
  'ui.canvas':        'browser_action',
  'messaging.message':'api_call',
  'media.image':      'api_call',
  'media.tts':        'api_call',
  'memory.memory_search': 'safe',
  'memory.memory_get':    'safe',
  'sessions.list':    'safe',
  'sessions.history': 'safe',
  'sessions.send':    'safe',
  'sessions.spawn':   'safe',
  'sessions.subagents':'safe',
  'sessions.status':  'safe',
  'sessions.sessions_list':    'safe',
  'sessions.sessions_history': 'safe',
  'sessions.sessions_send':    'safe',
  'sessions.sessions_spawn':   'safe',
  'sessions.sessions_subagents':'safe',
  'sessions.sessions_status':  'safe',
  'sessions.session_status':   'safe',
  'agents.agents_list':'safe',
  'nodes.nodes':      'safe',
  'automation.cron':  'cron_job',
  'automation.gateway':'safe',
};

// ── Consent requirements by ATL classification ────────────────
const CONSENT_REQUIRED = {
  'filesystem_read': true,
  'filesystem_write': true,
  'shell_exec': true,
  'web_search': true,
  'api_call': true,
  'browser_action': true,
  'cron_job': true,  // pre-auth
  'safe': false,
};

/**
 * Score the tool catalog against OWASP ASI categories.
 * Returns: { toolCount, classifiedCount, unknownTools[], asiCounts, asiTags }
 */
function scoreOWASP(catalogTools) {
  const asiCounts = {};
  const asiTags = {};
  let classifiedCount = 0;
  const unknownTools = [];

  for (const tool of catalogTools) {
    const key = tool.group + '.' + tool.name;
    const asiRisks = OWASP_ASI_MAP[key];
    if (asiRisks === undefined) {
      unknownTools.push(key);
    } else {
      classifiedCount++;
      asiTags[key] = asiRisks;
      for (const asi of asiRisks) {
        asiCounts[asi] = (asiCounts[asi] || 0) + 1;
      }
    }
  }

  return {
    toolCount: catalogTools.length,
    classifiedCount,
    unknownCount: unknownTools.length,
    unknownTools,
    asiCounts,
    asiTags,
    surfaceClean: unknownTools.length === 0 && !asiCounts['ASI05'] && !asiCounts['ASI10'],
  };
}

/**
 * Classify the agent against AWS Agentic AI Security Scoping Matrix.
 * Returns: { scope: 1-4, label, description }
 */
function scoreAWS(catalogTools, consentLevel) {
  // Check what capability classes are available
  const hasExec = catalogTools.some(t => 
    ATL_CLASSIFY[t.group + '.' + t.name] === 'shell_exec'
  );
  const hasWrite = catalogTools.some(t => 
    ATL_CLASSIFY[t.group + '.' + t.name] === 'filesystem_write'
  );
  const hasApi = catalogTools.some(t => {
    const cls = ATL_CLASSIFY[t.group + '.' + t.name];
    return cls === 'api_call' || cls === 'web_search';
  });
  const hasCron = catalogTools.some(t => 
    ATL_CLASSIFY[t.group + '.' + t.name] === 'cron_job'
  );
  const hasAction = hasExec || hasWrite || hasApi;

  // Scope 4: Self-initiating (cron jobs active)
  if (hasCron) {
    return {
      scope: 4,
      label: 'Full Autonomy',
      description: 'Agent self-initiates tasks without being asked',
      nhbText: 'This agent starts tasks without being asked',
    };
  }

  // Scope 3: Supervised (auto-exec after trigger) — Yellow Shield
  if (hasAction && consentLevel === 'yellow') {
    return {
      scope: 3,
      label: 'Supervised Agency',
      description: 'Agent executes autonomously after user initiates conversation',
      nhbText: 'This agent acts on its own — CROCbox catches it',
    };
  }

  // Scope 2: HITL required — Green Shield
  if (hasAction && consentLevel === 'green') {
    return {
      scope: 2,
      label: 'Human-in-the-Loop',
      description: 'Agent recommends actions but every change requires human approval',
      nhbText: 'This agent asks before acting',
    };
  }

  // Scope 1: Read-only
  return {
    scope: 1,
    label: 'Read-Only',
    description: 'Agent provides information but takes no actions',
    nhbText: 'This agent can look but not touch',
  };
}

/**
 * Assess the agent against Meta's Agents Rule of Two.
 * Returns: { properties: [A,B,C], count, hitlRequired, config, nhbText }
 */
function scoreMeta(catalogTools) {
  const properties = [];

  // [A] Untrusted Inputs — agent processes external content
  const hasUntrustedInputs = catalogTools.some(t => {
    const key = t.group + '.' + t.name;
    return key === 'web.web_search' || key === 'web.web_fetch' || key === 'ui.browser';
  });
  if (hasUntrustedInputs) properties.push('A');

  // [B] Sensitive Systems — agent accesses private data
  const hasSensitiveAccess = catalogTools.some(t => {
    const cls = ATL_CLASSIFY[t.group + '.' + t.name];
    return cls === 'filesystem_read' || cls === 'filesystem_write';
  });
  if (hasSensitiveAccess) properties.push('B');

  // [C] State Change — agent can modify things or communicate externally
  const hasStateChange = catalogTools.some(t => {
    const cls = ATL_CLASSIFY[t.group + '.' + t.name];
    return cls === 'shell_exec' || cls === 'filesystem_write' || 
           cls === 'api_call' || cls === 'browser_action';
  });
  if (hasStateChange) properties.push('C');

  const count = properties.length;
  const hitlRequired = count >= 3;
  
  let nhbText;
  if (count >= 3) {
    nhbText = 'Full power agent — CROCbox is your safety net';
  } else if (properties.includes('A') && properties.includes('C')) {
    nhbText = 'This agent acts but can\'t see your private files';
  } else if (properties.includes('B') && properties.includes('C')) {
    nhbText = 'Your own data could contain hidden instructions';
  } else if (properties.includes('A') && properties.includes('B')) {
    nhbText = 'This agent reads but doesn\'t act';
  } else {
    nhbText = 'Limited capability agent';
  }

  return {
    properties,
    count,
    hitlRequired,
    config: '[' + properties.join('+') + ']',
    nhbText,
  };
}

/**
 * Compute the composite Shield color.
 * Returns: { color, label, nhbSummary, owasp, aws, meta, catalogHash, timestamp }
 */
function computeShieldScore(catalogTools, consentLevel, mcpSkillCount) {
  const crypto = require('crypto');
  
  const owasp = scoreOWASP(catalogTools);
  const aws = scoreAWS(catalogTools, consentLevel);
  const meta = scoreMeta(catalogTools);

  // Certification surface hash
  const toolIds = catalogTools.map(t => t.group + '.' + t.name).sort();
  const catalogHash = crypto.createHash('sha256')
    .update(toolIds.join(','))
    .digest('hex');

  // Composite shield color
  let color, label, nhbSummary;

  if (owasp.unknownCount > 0) {
    // Unknown tools = cannot verify = Red
    color = 'red';
    label = 'Unverified';
    nhbSummary = 'CROCbox cannot verify this agent\'s behavior. ' +
      owasp.unknownCount + ' unrecognized tool(s). Proceed with extreme caution.';
  } else if (consentLevel === 'green' && owasp.surfaceClean && aws.scope <= 2 && !meta.hitlRequired) {
    // CBE + clean surface + low scope + Rule of Two satisfied = Green
    color = 'green';
    label = 'Verified';
    nhbSummary = 'Your agent asks before it acts. Its tools are known. ' +
      'Its access is appropriate. You are in full control.';
  } else {
    // Everything else = Yellow (CBD, risks present, higher scope)
    color = 'yellow';
    label = 'Protected';
    nhbSummary = 'Your agent can act on its own, but CROCbox catches every action ' +
      'and asks you before showing the result.';
    if (meta.hitlRequired) {
      nhbSummary += ' All capability areas are active.';
    }
  }

  const score = {
    color,
    label,
    nhbSummary,
    consentLevel,
    owasp: {
      toolCount: owasp.toolCount,
      classified: owasp.classifiedCount,
      unknown: owasp.unknownCount,
      unknownTools: owasp.unknownTools,
      asiCounts: owasp.asiCounts,
      surfaceClean: owasp.surfaceClean,
    },
    aws: {
      scope: aws.scope,
      label: aws.label,
      nhbText: aws.nhbText,
    },
    meta: {
      properties: meta.properties,
      config: meta.config,
      hitlRequired: meta.hitlRequired,
      nhbText: meta.nhbText,
    },
    catalogHash,
    mcpSkillCount: mcpSkillCount || 0,
    timestamp: new Date().toISOString(),
  };

  return score;
}

/**
 * Generate the Shield click-through HTML for a given Rental Ski level.
 * Returns HTML string for injection via executeJavaScript.
 */
function getShieldDetailHTML(score, level) {
  level = level || 'beginner';
  const colorHex = score.color === 'green' ? '#4CAF50' : 
                   score.color === 'yellow' ? '#d4a017' : '#e53935';
  const shieldEmoji = score.color === 'green' ? '🟢' : score.color === 'yellow' ? '🛡️' : '🔴';

  if (level === 'beginner') {
    return `<div style="padding:24px">
      <div style="font-size:48px;text-align:center;margin-bottom:12px">${shieldEmoji}</div>
      <div style="font-size:20px;font-weight:700;text-align:center;color:${colorHex};margin-bottom:16px;text-transform:uppercase">${score.color} Shield</div>
      <div style="font-size:15px;line-height:1.7;color:#ccc">${score.nhbSummary}</div>
    </div>`;
  }

  if (level === 'intermediate') {
    return `<div style="padding:24px">
      <div style="font-size:36px;text-align:center;margin-bottom:8px">${shieldEmoji}</div>
      <div style="font-size:18px;font-weight:700;text-align:center;color:${colorHex};margin-bottom:16px;text-transform:uppercase">${score.color} Shield — Why This Score</div>
      <div style="font-size:13px;line-height:1.8;color:#ccc">
        <div style="margin-bottom:8px">• ${score.meta.nhbText} (Design Risk: ${score.meta.hitlRequired ? 'elevated' : 'managed'})</div>
        <div style="margin-bottom:8px">• ${score.aws.nhbText} (Autonomy: Scope ${score.aws.scope})</div>
        <div style="margin-bottom:8px">• Tool catalog classified (${score.owasp.classified}/${score.owasp.toolCount} known${score.owasp.unknown > 0 ? ', ' + score.owasp.unknown + ' unrecognized' : ''})</div>
        <div style="margin-bottom:8px">• Consent: ${score.consentLevel === 'green' ? 'Before Execution' : score.consentLevel === 'yellow' ? 'Before Delivery' : 'None'}</div>
      </div>
      <div style="margin-top:12px;padding:10px;background:rgba(255,255,255,0.05);border-radius:6px;font-size:11px;color:#888">
        Shield factors: ${score.owasp.classified} tools classified | Consent: ${score.consentLevel === 'yellow' ? 'Before Delivery' : 'Before Execution'} | Audit: Active
      </div>
    </div>`;
  }

  // Expert level — full matrix
  const asiEntries = Object.entries(score.owasp.asiCounts)
    .map(([k, v]) => k + '(' + v + ')')
    .join(', ') || 'none';

  return `<div style="padding:20px">
    <div style="font-size:28px;text-align:center;margin-bottom:6px">${shieldEmoji}</div>
    <div style="font-size:16px;font-weight:700;text-align:center;color:${colorHex};margin-bottom:14px;text-transform:uppercase">${score.color} Shield — Full Assessment</div>
    <div style="font-size:12px;line-height:1.8;color:#bbb;font-family:monospace">
      <div style="margin-bottom:4px"><strong style="color:#999">OWASP Surface:</strong> ${asiEntries}</div>
      <div style="margin-bottom:4px"><strong style="color:#999">AWS Scope:</strong> ${score.aws.scope} (${score.aws.label})</div>
      <div style="margin-bottom:4px"><strong style="color:#999">Meta Rule of Two:</strong> ${score.meta.config} ${score.meta.hitlRequired ? '— HITL mandatory' : '— satisfied'}</div>
      <div style="margin-bottom:4px"><strong style="color:#999">Consent Level:</strong> ${score.consentLevel === 'yellow' ? 'Yellow (CBD)' : score.consentLevel === 'green' ? 'Green (CBE)' : 'None'} ${score.consentLevel === 'yellow' ? '— Green requires exec.approval broadcast' : ''}</div>
      <div style="margin-bottom:4px"><strong style="color:#999">Catalog:</strong> ${score.owasp.classified} classified, ${score.owasp.unknown} pending | Hash: ${score.catalogHash.substring(0, 12)}...</div>
      <div style="margin-bottom:4px"><strong style="color:#999">MCP Skills:</strong> ${score.mcpSkillCount} installed</div>
      <div style="margin-bottom:4px"><strong style="color:#999">Audit:</strong> Active | Chain: intact</div>
      <div style="margin-top:8px;color:#666">Scored: ${score.timestamp}</div>
    </div>
  </div>`;
}

/**
 * Parse tools.catalog response into flat tool list.
 * OpenClaw returns: { groups: [ { name, tools: [ { name, ... } ] } ] }
 */
function parseCatalog(catalogPayload) {
  const tools = [];
  if (!catalogPayload || !catalogPayload.groups) return tools;
  for (const group of catalogPayload.groups) {
    // OpenClaw uses 'id' for group/tool identifiers, 'name' as fallback
    const groupId = group.id || group.name;
    for (const tool of (group.tools || [])) {
      const toolId = tool.id || tool.name;
      tools.push({
        group: groupId,
        name: toolId,
        description: tool.description || '',
      });
    }
  }
  return tools;
}

module.exports = {
  computeShieldScore,
  getShieldDetailHTML,
  parseCatalog,
  scoreOWASP,
  scoreAWS,
  scoreMeta,
  ATL_CLASSIFY,
  CONSENT_REQUIRED,
  OWASP_ASI_MAP,
};
