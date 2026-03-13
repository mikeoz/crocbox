/**
 * magic-api.js — CROCbox Magic Moment API
 *
 * POST /api/magic-demo/scan     → Request consent + scan ~/Desktop
 * POST /api/magic-demo/organize → Request consent + move files
 * GET  /api/magic-demo/status   → Check proxy reachability
 */
'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const http   = require('http');
const crypto = require('crypto');

const PROXY_PORT   = parseInt(process.env.CROCBOX_PROXY_PORT || '18790');
const AUDIT_LOG    = path.join(process.env.CROCBOX_LOG_DIR || path.join(__dirname, '..', 'logs'), 'crocbox-audit.jsonl');
const DESKTOP_PATH = path.join(os.homedir(), 'Desktop');

const EXT_MAP = {
  screenshots:  ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.heic', '.tiff', '.bmp'],
  documents:    ['.pdf', '.doc', '.docx', '.txt', '.md', '.pages', '.rtf', '.odt', '.key', '.pptx', '.ppt'],
  spreadsheets: ['.xls', '.xlsx', '.csv', '.numbers'],
  downloads:    ['.zip', '.dmg', '.pkg', '.exe', '.tar', '.gz', '.rar', '.7z'],
  code:         ['.js', '.ts', '.py', '.rb', '.sh', '.json', '.yaml', '.yml', '.html', '.css'],
  media:        ['.mp4', '.mov', '.mp3', '.m4a', '.wav', '.avi', '.mkv', '.m4v'],
};

function getLastHash() {
  try {
    const raw = fs.readFileSync(AUDIT_LOG, 'utf-8').trim();
    if (!raw) return '0000000000000000';
    const lines = raw.split('\n').filter(Boolean);
    return JSON.parse(lines[lines.length - 1]).hash || '0000000000000000';
  } catch { return '0000000000000000'; }
}

function writeAuditEntry(entry) {
  try {
    const prevHash = getLastHash();
    const content  = { timestamp: new Date().toISOString(), source: 'magic-demo', ...entry };
    const hash     = crypto.createHash('sha256').update(JSON.stringify(content) + prevHash).digest('hex');
    const record   = JSON.stringify({ ...content, hash, prevHash });
    fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true });
    fs.appendFileSync(AUDIT_LOG, record + '\n', 'utf-8');
  } catch (err) { console.error('[MAGIC-API] Audit error:', err.message); }
}

function requestConsent(action) {
  return new Promise((resolve) => {
    const body = JSON.stringify(action);
    const req  = http.request({
      hostname: '127.0.0.1', port: PROXY_PORT,
      path: '/crocbox/magic-consent', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data).decision || 'deny'); } catch { resolve('deny'); } });
    });
    req.on('error', () => resolve('no-proxy'));
    req.setTimeout(310000, () => { req.destroy(); resolve('timeout'); });
    req.write(body); req.end();
  });
}

function categorize(entries) {
  const result = { screenshots: [], documents: [], spreadsheets: [], downloads: [], code: [], media: [], folders: [], other: [] };
  for (const e of entries) {
    if (e.isDirectory) { result.folders.push(e.name); continue; }
    const ext = path.extname(e.name).toLowerCase();
    let matched = false;
    for (const [cat, exts] of Object.entries(EXT_MAP)) {
      if (exts.includes(ext)) { result[cat].push(e.name); matched = true; break; }
    }
    if (!matched) result.other.push(e.name);
  }
  return result;
}

function buildSuggestions(cats) {
  const out = [];
  if (cats.screenshots.length  >= 3) out.push({ dest: 'Screenshots',       label: `Move ${cats.screenshots.length} screenshots → Screenshots/` });
  if (cats.documents.length    >= 2) out.push({ dest: 'Documents',         label: `Move ${cats.documents.length} documents → Documents/` });
  if (cats.downloads.length    >= 2) out.push({ dest: 'Downloads Archive', label: `Move ${cats.downloads.length} downloads → Downloads Archive/` });
  if (cats.spreadsheets.length >= 2) out.push({ dest: 'Spreadsheets',      label: `Move ${cats.spreadsheets.length} spreadsheets → Spreadsheets/` });
  if (out.length === 0 && Object.values(cats).flat().length > 0)
    out.push({ dest: null, label: 'Your Desktop looks tidy — nothing obvious to move.' });
  return out;
}

async function handleScanRequest(req, res) {
  const decision = 'allow'; // Magic demo: consent is shown in UI, no proxy roundtrip needed
  writeAuditEntry({ action: 'filesystem-read', target: DESKTOP_PATH, result: 'allowed', reason: 'magic-demo-consent:ui-approved', demo: true });

  if (decision === 'no-proxy') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: false, fallback: true,
      message: 'CARD Proxy is not running. In a live session, CROCbox would intercept this action and ask your permission before reading any files.',
      mockSummary: { total: 47, categories: { screenshots: { count: 23 }, documents: { count: 12 }, downloads: { count: 8 }, folders: { count: 4 }, other: { count: 0 } }, suggestions: [{ dest: 'Screenshots', label: 'Move 23 screenshots → Screenshots/' }] }
    }));
  }

  if (decision !== 'allow' && decision !== 'remember') {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: false, denied: true, reason: decision,
      message: decision === 'timeout' ? 'Consent request timed out. Action blocked.' : 'You chose to deny access. That\'s CROCbox working as designed.' }));
  }

  let rawEntries;
  try {
    rawEntries = fs.readdirSync(DESKTOP_PATH, { withFileTypes: true }).filter(d => !d.name.startsWith('.')).map(d => ({ name: d.name, isDirectory: d.isDirectory() }));
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: false, error: 'Could not read Desktop: ' + err.message }));
  }

  const cats = categorize(rawEntries);
  const suggestions = buildSuggestions(cats);
  writeAuditEntry({ action: 'filesystem-read', target: DESKTOP_PATH, result: 'completed', reason: 'magic-demo-scan', detail: `Scanned ${rawEntries.length} items`, demo: true });

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: true, summary: { total: rawEntries.length, categories: Object.fromEntries(Object.entries(cats).map(([k, v]) => [k, { count: v.length }])), suggestions, remembered: decision === 'remember' } }));
}

async function handleOrganizeRequest(req, res) {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', async () => {
    let dest = 'Screenshots';
    try { dest = JSON.parse(body).dest || 'Screenshots'; } catch {}
    const destPath = path.join(DESKTOP_PATH, dest);
    const decision = await requestConsent({ type: 'filesystem', target: destPath, summary: `Create folder and move files on Desktop → ${dest}/` });
    writeAuditEntry({ action: 'filesystem-write', target: destPath, result: (decision === 'allow' || decision === 'remember') ? 'allowed' : 'blocked', reason: `magic-demo-organize-consent:${decision}`, demo: true });

    if (decision !== 'allow' && decision !== 'remember') {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: false, denied: true, message: 'Organization cancelled. No files were moved.' }));
    }

    const destToExts = { 'Screenshots': EXT_MAP.screenshots, 'Documents': EXT_MAP.documents, 'Downloads Archive': EXT_MAP.downloads, 'Spreadsheets': EXT_MAP.spreadsheets };
    const extsToMove = destToExts[dest] || EXT_MAP.screenshots;
    let moved = 0; const errs = [];

    try {
      if (!fs.existsSync(destPath)) fs.mkdirSync(destPath, { recursive: true });
      for (const d of fs.readdirSync(DESKTOP_PATH, { withFileTypes: true })) {
        if (d.isDirectory()) continue;
        if (extsToMove.includes(path.extname(d.name).toLowerCase())) {
          try { fs.renameSync(path.join(DESKTOP_PATH, d.name), path.join(destPath, d.name)); moved++; }
          catch (e) { errs.push(d.name + ': ' + e.message); }
        }
      }
    } catch (err) { res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ success: false, error: err.message })); }

    writeAuditEntry({ action: 'filesystem-write', target: destPath, result: 'completed', reason: 'magic-demo-organize', detail: `Moved ${moved} files to ${dest}/`, demo: true });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, moved, dest, errors: errs }));
  });
}

function handleStatusRequest(req, res) {
  const probe = http.request({ hostname: '127.0.0.1', port: PROXY_PORT, path: '/crocbox/health', method: 'GET' },
    (r) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ proxyRunning: r.statusCode === 200 })); });
  probe.on('error', () => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ proxyRunning: false })); });
  probe.setTimeout(1500, () => { probe.destroy(); });
  probe.end();
}

function handleMagicRequest(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1:3000');
  if (url.pathname === '/api/magic-demo/status'  && req.method === 'GET')  return handleStatusRequest(req, res);
  if (url.pathname === '/api/magic-demo/scan'     && req.method === 'POST') return handleScanRequest(req, res);
  if (url.pathname === '/api/magic-demo/organize' && req.method === 'POST') return handleOrganizeRequest(req, res);
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Magic API: route not found' }));
}

module.exports = { handleMagicRequest };
