/**
 * CROCbox — AI Bridge (ai-bridge.js)
 * Local HTTP proxy that routes OpenClaw gateway model calls through opn.li ai-proxy.
 * The gateway thinks it's talking to a local OpenAI-compatible provider.
 * The bridge attaches the member's Supabase JWT and forwards to ai-proxy.
 * The bridge reads the member's model preference from the database.
 *
 * The member carries membership, not a provider key.
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const BRIDGE_PORT = 18790;
const ACCOUNT_PATH = path.join(process.env.HOME || '/tmp', '.crocbox', 'account.json');

const SUPABASE_URL = 'https://qmpmxrtcysrngfjotkcq.supabase.co';
const AI_PROXY_URL = SUPABASE_URL + '/functions/v1/ai-proxy';
const AUTH_URL = SUPABASE_URL + '/auth/v1/token?grant_type=refresh_token';
const REST_URL = SUPABASE_URL + '/rest/v1';

const DEFAULT_MODEL = 'anthropic/claude-sonnet-5';
const MODEL_REFRESH_MS = 5 * 60 * 1000; // Re-check preference every 5 minutes

let currentAccessToken = null;
let currentRefreshToken = null;
let currentAnonKey = null;
let currentMemberId = null;
let tokenExpiry = 0;

let memberModel = DEFAULT_MODEL;
let modelFetchedAt = 0;

function loadAccount() {
  try {
    const acct = JSON.parse(fs.readFileSync(ACCOUNT_PATH, 'utf8'));
    currentAccessToken = acct.access_token || null;
    currentRefreshToken = acct.refresh_token || null;
    currentAnonKey = acct.anon_key || null;
    currentMemberId = acct.member_id || null;
    if (currentAccessToken) {
      try {
        const payload = JSON.parse(Buffer.from(currentAccessToken.split('.')[1], 'base64').toString());
        tokenExpiry = (payload.exp || 0) * 1000;
      } catch (e) {
        tokenExpiry = 0;
      }
    }
    console.log('[ai-bridge] Account loaded. member_id: ' + currentMemberId);
    console.log('[ai-bridge] Token expires: ' + new Date(tokenExpiry).toISOString());
    return true;
  } catch (e) {
    console.error('[ai-bridge] Could not load account.json:', e.message);
    return false;
  }
}

function isTokenExpired() {
  return Date.now() > (tokenExpiry - 60000);
}

async function refreshToken() {
  if (!currentRefreshToken || !currentAnonKey) {
    console.error('[ai-bridge] No refresh_token or anon_key — cannot refresh');
    return false;
  }
  console.log('[ai-bridge] Refreshing Supabase token...');
  const body = JSON.stringify({ refresh_token: currentRefreshToken });
  return new Promise((resolve) => {
    const url = new URL(AUTH_URL);
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': currentAnonKey,
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.access_token && parsed.refresh_token) {
            currentAccessToken = parsed.access_token;
            currentRefreshToken = parsed.refresh_token;
            try {
              const payload = JSON.parse(Buffer.from(currentAccessToken.split('.')[1], 'base64').toString());
              tokenExpiry = (payload.exp || 0) * 1000;
            } catch (e) { tokenExpiry = Date.now() + 3600000; }
            try {
              const acct = JSON.parse(fs.readFileSync(ACCOUNT_PATH, 'utf8'));
              acct.access_token = currentAccessToken;
              acct.refresh_token = currentRefreshToken;
              fs.writeFileSync(ACCOUNT_PATH, JSON.stringify(acct, null, 2), 'utf8');
            } catch (e) { console.error('[ai-bridge] Could not update account.json:', e.message); }
            console.log('[ai-bridge] Token refreshed. New expiry: ' + new Date(tokenExpiry).toISOString());
            resolve(true);
          } else {
            console.error('[ai-bridge] Refresh failed:', data.substring(0, 200));
            resolve(false);
          }
        } catch (e) {
          console.error('[ai-bridge] Refresh parse error:', e.message);
          resolve(false);
        }
      });
    });
    req.on('error', (e) => {
      console.error('[ai-bridge] Refresh request error:', e.message);
      resolve(false);
    });
    req.write(body);
    req.end();
  });
}

async function ensureValidToken() {
  if (!currentAccessToken) loadAccount();
  if (isTokenExpired()) {
    const ok = await refreshToken();
    if (!ok) return false;
  }
  return true;
}

async function fetchMemberModel() {
  if (!currentMemberId || !currentAnonKey || !currentAccessToken) return;
  if (Date.now() - modelFetchedAt < MODEL_REFRESH_MS) return;

  const encodedId = encodeURIComponent(currentMemberId);
  const restPath = '/rest/v1/member_ai_prefs?select=selected_model_id&member_id=eq.' + encodedId;

  return new Promise((resolve) => {
    const url = new URL(SUPABASE_URL + restPath);
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + currentAccessToken,
        'apikey': currentAnonKey,
        'Accept': 'application/json'
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const rows = JSON.parse(data);
          if (Array.isArray(rows) && rows.length > 0 && rows[0].selected_model_id) {
            memberModel = rows[0].selected_model_id;
            console.log('[ai-bridge] Member model preference: ' + memberModel);
          } else {
            console.log('[ai-bridge] No model preference found, using default: ' + DEFAULT_MODEL);
            memberModel = DEFAULT_MODEL;
          }
          modelFetchedAt = Date.now();
        } catch (e) {
          console.error('[ai-bridge] Model pref parse error:', e.message);
        }
        resolve();
      });
    });
    req.on('error', (e) => {
      console.error('[ai-bridge] Model pref fetch error:', e.message);
      resolve();
    });
    req.end();
  });
}

let server = null;

function startBridge() {
  loadAccount();

  server = http.createServer(async (req, res) => {
    if (req.method !== 'POST' || !req.url.endsWith('/chat/completions')) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }

    let rawBody = '';
    for await (const chunk of req) { rawBody += chunk; }

    const tokenOk = await ensureValidToken();
    if (!tokenOk) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'token_refresh_failed', message: 'Could not authenticate to opn.li. Please restart CROCbox.' }));
      return;
    }

    // Fetch member's model preference (cached, refreshes every 5 min)
    await fetchMemberModel();

    // Replace the model in the request body with the member's preference
    let parsed;
    try {
      parsed = JSON.parse(rawBody);
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'bad_request', message: 'Invalid JSON' }));
      return;
    }

    const gatewayModel = parsed.model || '(none)';
    parsed.model = memberModel;
    parsed.source_product = 'crocbox';
    const body = JSON.stringify(parsed);

    console.log('[ai-bridge] Model: gateway sent ' + gatewayModel + ' → using ' + memberModel);

    const url = new URL(AI_PROXY_URL);
    const proxyReq = https.request({
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + currentAccessToken,
        'Content-Length': Buffer.byteLength(body)
      }
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (e) => {
      console.error('[ai-bridge] Proxy request error:', e.message);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'proxy_error', message: e.message }));
      }
    });

    proxyReq.write(body);
    proxyReq.end();
  });

  server.listen(BRIDGE_PORT, '127.0.0.1', () => {
    console.log('[ai-bridge] Listening on http://127.0.0.1:' + BRIDGE_PORT);
  });

  server.on('error', (e) => {
    console.error('[ai-bridge] Server error:', e.message);
  });

  return server;
}

function stopBridge() {
  if (server) {
    server.close();
    server = null;
    console.log('[ai-bridge] Stopped.');
  }
}

module.exports = { startBridge, stopBridge, loadAccount };