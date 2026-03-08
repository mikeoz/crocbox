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
      provider: env.AI_PROVIDER || '',
      apiKey: env.AI_API_KEY || ''
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
        const { prompt } = JSON.parse(body);
        if (!prompt) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'No prompt provided.' }));
        }

        const env = readEnv();
        const apiKey = env.AI_API_KEY;
        const provider = env.AI_PROVIDER || 'anthropic';

        if (!apiKey) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'No AI API key configured. Go to Settings to add one.' }));
        }

        // Route through the CARD Proxy gateway so consent fires
        const proxyPort = parseInt(env.CROCBOX_PROXY_PORT) || 18790;
        const http = require('http');
        const https = require('https');

        // Call Anthropic API — routed through CARD Proxy
        const payload = JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 1024,
          messages: [{ role: 'user', content: prompt }]
        });

        const options = {
          hostname: 'api.anthropic.com',
          port: 443,
          path: '/v1/messages',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'Content-Length': Buffer.byteLength(payload)
          }
        };

        const apiReq = https.request(options, (apiRes) => {
          let data = '';
          apiRes.on('data', chunk => { data += chunk; });
          apiRes.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              if (parsed.error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: parsed.error.message }));
              } else {
                const reply = parsed.content && parsed.content[0] && parsed.content[0].text;
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, reply }));
              }
            } catch (e) {
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Failed to parse AI response.' }));
            }
          });
        });

        apiReq.on('error', (e) => {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        });

        apiReq.write(payload);
        apiReq.end();

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
