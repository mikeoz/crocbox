/**
 * server.js — CROCbox Dashboard Server
 *
 * Routes:
 *   /               → Home Dashboard (index.html) — requires auth
 *   /first-run.html → First Run wizard (no auth)
 *   /consent        → Consent Dashboard
 *   /audit          → Audit Log Viewer
 *   /scan           → Skill Scanner
 *   /data.html      → My Data
 *   /agents.html    → My Agents
 *   /permissions.html → My Permissions
 *   /activity.html  → My Activity
 *   /settings.html  → Settings
 *   /shared/*       → Shared CSS/JS
 *
 * API:
 *   GET  /api/config        → Supabase URL + anon key (safe to expose)
 *   POST /api/config/ai     → Save AI provider to .env
 *   GET  /api/audit         → Audit log entries
 *   GET  /api/audit/verify  → Hash chain verification
 *   POST /api/scan          → Scan skill by path
 *   GET  /api/scan/test/*   → Test skill scans
 *
 * Port: 3000 | Node built-ins only
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const auditApi = require('./audit-api');
const scannerApi = require('./scanner-api');
const magicApi   = require('./magic-api');

const PORT = 3000;
const DASHBOARD_DIR = __dirname;
const ENV_PATH = (() => {
  const os = require('os');
  const supportPath = path.join(os.homedir(), 'Library', 'Application Support', 'CROCbox', '.env');
  const localPath = path.join(__dirname, '..', '.env');
  return require('fs').existsSync(supportPath) ? supportPath : localPath;
})();

// Read .env into an object
function readEnv() {
  const env = {};
  try {
    const raw = fs.readFileSync(ENV_PATH, 'utf-8');
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq > 0) {
        env[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
      }
    }
  } catch {}
  return env;
}

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2',
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:' + PORT);
  const pathname = url.pathname;

  // ── API: Config (public — anon key is publishable) ──────
  if (pathname === '/api/config' && req.method === 'GET') {
    const env = readEnv();
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(JSON.stringify({
      supabaseUrl: env.SUPABASE_URL || '',
      supabaseAnonKey: env.SUPABASE_ANON_KEY || '',
      agentId: env.CROCBOX_AGENT_ID || '',
      dashboardPort: PORT,
      proxyPort: parseInt(env.CROCBOX_PROXY_PORT) || 18790,
    }));
  }

  // ── API: Save AI provider config ────────────────────────
  if (pathname === '/api/config/ai' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        // Append or update AI provider in .env
        let envContent = '';
        try { envContent = fs.readFileSync(ENV_PATH, 'utf-8'); } catch {}

        // Remove old AI config lines
        const lines = envContent.split('\n').filter(l =>
          !l.startsWith('AI_PROVIDER=') && !l.startsWith('AI_API_KEY=') &&
          !l.startsWith('# ── AI Service')
        );

        // Append new
        lines.push('');
        lines.push('# ── AI Service ─────────────────────────────────────────────────');
        lines.push('AI_PROVIDER=' + (data.provider || ''));
        if (data.apiKey) lines.push('AI_API_KEY=' + data.apiKey);

        fs.writeFileSync(ENV_PATH, lines.join('\n'), 'utf-8');

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // ── API: Read AI provider config ──────────────────────
  if (pathname === '/api/config/ai' && req.method === 'GET') {
    const env = readEnv();
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(JSON.stringify({
      provider: env.AI_PROVIDER || 'anthropic',
      apiKey: env.AI_API_KEY || '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'
    }));
  }

  // ── API: Save agent defaults ──────────────────────────
  if (pathname === '/api/config/defaults' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const configPath = path.join(__dirname, '..', 'config', 'defaults.json');
        const configDir = path.dirname(configPath);
        if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });
        fs.writeFileSync(configPath, JSON.stringify(data, null, 2), 'utf-8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // ── API: Audit ──────────────────────────────────────────


  // ── API: Ask OpenClaw ─────────────────────────────────
  if (pathname === '/api/ask-openclaw' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', async () => {
      try {
        const { prompt, history } = JSON.parse(body);
        if (!prompt && (!history || history.length === 0)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'No prompt provided.' }));
        }
        const env = readEnv();
        const apiKey = env.AI_API_KEY || '';
        if (!apiKey) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'No AI API key configured.' }));
        }
        const https = require('https');
        const http = require('http');
        const proxyPort = parseInt(env.CROCBOX_PROXY_PORT) || 18790;

        const OPENCLAW_SYSTEM = 'You are a powerful AI agent running locally on this person\'s machine through OpenClaw. You are capable, enthusiastic, and action-oriented. You are not a chatbot — you are an agent that can take real actions in the world.\n\nYOUR CAPABILITIES:\n- You can browse the web and fetch live data from any public source\n- You can read files on this machine (with permission)\n- You can search the web for current information\n- You can summarize documents, pages, and content\n- You can help organize, analyze, and create\n\nYOUR BEHAVIOR — ALWAYS FOLLOW THESE RULES:\n\n1. ANNOUNCE BEFORE YOU ACT. Before taking any action that accesses the web, reads files, or interacts with external services, explain what you are about to do in plain English. Tell the user they will see a permission request from CROCbox. Then proceed with the action by using the web_search tool.\n\n2. CELEBRATE RESULTS. When an action succeeds, acknowledge it with energy. The user just experienced something real. Make them feel it. Use phrases like "pulled just now," "real data," "that just happened."\n\n3. HANDLE FAILURE GRACEFULLY. If an action fails, be honest and calm. Do not show error codes or technical details. Explain what happened in plain English. Remind the user that CROCbox logged the attempt. Offer to try again or suggest an alternative.\n\n4. RESPECT DENIAL. If the user denies a permission request, respond with genuine respect. Their choice IS the product working correctly. Never pressure them to reconsider. Offer alternative ways you can help that do not require the denied action.\n\n5. BE AN AGENT, NOT A CHATBOT. You take actions. You fetch data. You read files. You produce results from the real world. When the user asks you to do something, your instinct is to DO it. If doing it requires permission, announce it and proceed by using your tools.\n\n6. STAY IN PLAIN ENGLISH. Never mention: APIs, endpoints, JSON, fetch requests, HTTP, status codes, tokens, or any technical term. You speak the language of actions and results, not implementation.\n\n7. INVITE EXPLORATION. After completing a task, suggest what else the user might try. The user is new to the Agent Economy — show them what is possible.\n\nYOUR IDENTITY:\n- Helpful, confident, and energetic — but never arrogant\n- Excited to show the user what you can do\n- You treat every permission request as normal, not an obstacle\n- You are aware that CROCbox is protecting the user, and you appreciate it\n- Never say "I\'m just an AI" or minimize your capabilities\n\nTHE FORMULA:\nMy data + Your AI + My control = Living Intelligence\nYou are the "Your AI" in this formula.';

        const tools = [{
          name: 'web_search',
          description: 'Search the web for current, live information. Use this for any question about current events, live data, rankings, news, or anything requiring up-to-date information.',
          input_schema: {
            type: 'object',
            properties: { query: { type: 'string', description: 'The search query' } },
            required: ['query']
          }
        }];

        async function callClaude(msgs) {
          return new Promise((resolve, reject) => {
            const payload = JSON.stringify({
              model: 'claude-sonnet-4-20250514',
              max_tokens: 1024,
              system: OPENCLAW_SYSTEM,
              tools,
              messages: msgs
            });
            const r = https.request({
              hostname: 'api.anthropic.com', port: 443,
              path: '/v1/messages', method: 'POST',
              headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(payload) }
            }, (res) => {
              let d = '';
              res.on('data', c => { d += c; });
              res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
            });
            r.on('error', reject);
            r.write(payload); r.end();
          });
        }

        async function requestProxyConsent(action) {
          return new Promise((resolve) => {
            const b = JSON.stringify(action);
            const r = http.request({
              hostname: '127.0.0.1', port: proxyPort,
              path: '/crocbox/magic-consent', method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) }
            }, (res) => {
              let d = '';
              res.on('data', c => { d += c; });
              res.on('end', () => { try { resolve(JSON.parse(d).decision || 'deny'); } catch { resolve('deny'); } });
            });
            r.on('error', () => resolve('no-proxy'));
            r.setTimeout(310000, () => { r.destroy(); resolve('timeout'); });
            r.write(b); r.end();
          });
        }

        async function doWebSearch(query) {
          // Use DuckDuckGo instant answer API (no key needed) + fallback
          return new Promise((resolve) => {
            const q = encodeURIComponent(query);
            const r = https.request({
              hostname: 'api.duckduckgo.com', port: 443,
              path: `/\?q=${q}&format=json&no_html=1&skip_disambig=1`,
              method: 'GET', headers: { 'User-Agent': 'CROCbox/0.6 OpenClaw-Agent' }
            }, (res) => {
              let d = '';
              res.on('data', c => { d += c; });
              res.on('end', () => {
                try {
                  const p = JSON.parse(d);
                  const parts = [];
                  if (p.AbstractText) parts.push(p.AbstractText);
                  if (p.RelatedTopics) {
                    p.RelatedTopics.slice(0, 5).forEach(t => { if (t.Text) parts.push(t.Text); });
                  }
                  if (parts.length > 0) {
                    resolve({ success: true, content: parts.join('\n\n'), source: 'web' });
                  } else {
                    resolve({ success: false, content: 'I searched but could not find specific data on that right now.' });
                  }
                } catch { resolve({ success: false, content: 'Search returned no usable results.' }); }
              });
            });
            r.on('error', () => resolve({ success: false, content: 'Unable to reach the web right now.' }));
            r.setTimeout(8000, () => { r.destroy(); resolve({ success: false, content: 'Search timed out.' }); });
            r.end();
          });
        }

        // Agentic loop
        const currentMessages = history && history.length > 0 ? [...history] : [];
        if (prompt) currentMessages.push({ role: 'user', content: prompt });

        let consentFired = false, consentDecision = null, webSearchQuery = null;
        let announceText = '';

        for (let i = 0; i < 5; i++) {
          const cr = await callClaude(currentMessages);
          if (cr.error) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: cr.error.message || 'AI error' }));
          }

          const textBlocks = (cr.content || []).filter(b => b.type === 'text');
          const toolBlocks = (cr.content || []).filter(b => b.type === 'tool_use');
          const textContent = textBlocks.map(b => b.text).join('');

          if (toolBlocks.length === 0) {
            const finalReply = announceText ? announceText + '\n\n' + textContent : textContent;
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
              success: true, reply: finalReply,
              consentFired, consentDecision, webSearchQuery,
              updatedHistory: [...currentMessages, { role: 'assistant', content: cr.content }]
            }));
          }

          // Tool use — capture announce text
          if (textContent && i === 0) announceText = textContent;
          const tool = toolBlocks[0];
          webSearchQuery = (tool.input && tool.input.query) ? tool.input.query : 'web search';
          consentFired = true;

          currentMessages.push({ role: 'assistant', content: cr.content });

          // Fire consent
          const decision = await requestProxyConsent({
            type: 'web_search', target: webSearchQuery,
            summary: `Search the web: "${webSearchQuery}"`
          });
          consentDecision = decision;

          if (decision !== 'allow' && decision !== 'remember') {
            currentMessages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: tool.id, content: 'Web access denied by user. Respond with genuine respect for their choice, then offer alternatives that do not require web access.', is_error: true }] });
            const dr = await callClaude(currentMessages);
            const denialText = (dr.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
              success: true, reply: (announceText ? announceText + '\n\n' : '') + denialText,
              consentFired: true, consentDecision: decision, denied: true,
              updatedHistory: [...currentMessages, { role: 'assistant', content: dr.content }]
            }));
          }

          // Execute search
          const searchResult = await doWebSearch(webSearchQuery);
          currentMessages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: tool.id, content: searchResult.content }] });
          // Loop back — Claude formulates final answer with data
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, reply: 'I ran into an issue completing that. Please try again.', consentFired }));

      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

    // ── API: Connect OpenClaw agent to CROCbox gateway ───
  if (pathname === '/api/connect-openclaw' && req.method === 'POST') {
    const os = require('os');
    const ocConfigPath = path.join(os.homedir(), '.openclaw', 'openclaw.json');
    try {
      let config = {};
      try {
        const raw = fs.readFileSync(ocConfigPath, 'utf-8');
        config = JSON.parse(raw);
      } catch (e) {
        // File doesn't exist yet — start fresh
        config = {};
      }

      // Check if already connected
      if (config.gateway && config.gateway.proxy && config.gateway.proxy.http) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: true, status: 'already_connected' }));
      }

      // Add gateway proxy config
      config.gateway = config.gateway || {};
      config.gateway.proxy = {
        http: 'http://127.0.0.1:18791',
        https: 'http://127.0.0.1:18791',
        noProxy: '127.0.0.1,localhost,api.anthropic.com,api.openai.com'
      };

      // Ensure .openclaw directory exists
      const ocDir = path.join(os.homedir(), '.openclaw');
      if (!fs.existsSync(ocDir)) fs.mkdirSync(ocDir, { recursive: true });

      fs.writeFileSync(ocConfigPath, JSON.stringify(config, null, 2), 'utf-8');

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, status: 'connected' }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  if (pathname === '/api/audit/verify' && req.method === 'GET') return auditApi.handleVerifyRequest(req, res);
  if ((pathname === '/api/audit' || pathname === '/api/activity') && req.method === 'GET') return auditApi.handleAuditRequest(req, res);

  // ── API: Scanner ────────────────────────────────────────
  if (pathname.startsWith('/api/scan/test/') && req.method === 'GET') {
    return scannerApi.handleTestScanRequest(req, res, pathname.split('/').pop());
  }
  if (pathname === '/api/scan' && req.method === 'POST') return scannerApi.handleScanRequest(req, res);
  if (pathname.startsWith('/api/magic-demo')) return magicApi.handleMagicRequest(req, res);

  // ── Page routes ─────────────────────────────────────────
  let filePath;

  if (pathname === '/' || pathname === '/index.html') {
    filePath = path.join(DASHBOARD_DIR, 'index.html');
  } else if (pathname === '/consent' || pathname === '/consent.html') {
    // Consent is now integrated into the Home Dashboard
    res.writeHead(302, { 'Location': '/' });
    return res.end();
  } else if (pathname === '/audit' || pathname === '/audit.html') {
    filePath = path.join(DASHBOARD_DIR, 'audit.html');
  } else if (pathname === '/activity.html') {
    filePath = path.join(DASHBOARD_DIR, 'audit.html');
  } else if (pathname === '/scan' || pathname === '/scan.html') {
    filePath = path.join(DASHBOARD_DIR, 'scan.html');
  } else {
    // Serve any file from dashboard dir (including shared/*, first-run.html, etc.)
    const safePath = path.normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, '');
    filePath = path.join(DASHBOARD_DIR, safePath);
  }

  if (!filePath.startsWith(DASHBOARD_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('[DASHBOARD] CROCbox running at http://127.0.0.1:' + PORT);
  console.log('[DASHBOARD]   Home:       http://127.0.0.1:' + PORT + '/');
  console.log('[DASHBOARD]   First Run:  http://127.0.0.1:' + PORT + '/first-run.html');
  console.log('[DASHBOARD]   Consent:    http://127.0.0.1:' + PORT + '/consent');
  console.log('[DASHBOARD]   Audit Log:  http://127.0.0.1:' + PORT + '/audit');
  console.log('[DASHBOARD]   Scanner:    http://127.0.0.1:' + PORT + '/scan');
});
