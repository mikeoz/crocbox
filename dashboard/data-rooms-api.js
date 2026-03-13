/**
 * data-rooms-api.js — CROCbox Data Rooms (WP-6)
 *
 * Manages local filesystem Data Rooms:
 *   ~/Library/Application Support/CROCbox/data-rooms.json
 *
 * GET  /api/data-rooms          → list all rooms
 * POST /api/data-rooms          → add a custom room
 * POST /api/data-rooms/close    → "Close the Door" — revoke grants for a room
 * POST /api/data-rooms/open     → re-open a closed room
 * GET  /api/data-rooms/history  → access history for a room (from audit log)
 * GET  /api/data-rooms/resolve  → resolve a file path to its Data Room
 */
'use strict';
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const SUPPORT_DIR  = path.join(os.homedir(), 'Library', 'Application Support', 'CROCbox');
const ROOMS_FILE   = path.join(SUPPORT_DIR, 'data-rooms.json');
const DESKTOP_PATH = path.join(os.homedir(), 'Desktop');
const DOCS_PATH    = path.join(os.homedir(), 'Documents');
const DOWNLOADS_PATH = path.join(os.homedir(), 'Downloads');

const DEFAULT_ROOMS = [
  { id: 'desktop',   name: 'Desktop',   path: DESKTOP_PATH,   isDefault: true, closed: false },
  { id: 'documents', name: 'Documents', path: DOCS_PATH,      isDefault: true, closed: false },
  { id: 'downloads', name: 'Downloads', path: DOWNLOADS_PATH, isDefault: true, closed: false },
];

function ensureSupportDir() {
  if (!fs.existsSync(SUPPORT_DIR)) fs.mkdirSync(SUPPORT_DIR, { recursive: true });
}

function loadRooms() {
  ensureSupportDir();
  if (!fs.existsSync(ROOMS_FILE)) {
    fs.writeFileSync(ROOMS_FILE, JSON.stringify(DEFAULT_ROOMS, null, 2));
    return JSON.parse(JSON.stringify(DEFAULT_ROOMS));
  }
  try {
    return JSON.parse(fs.readFileSync(ROOMS_FILE, 'utf8'));
  } catch {
    return JSON.parse(JSON.stringify(DEFAULT_ROOMS));
  }
}

function saveRooms(rooms) {
  ensureSupportDir();
  fs.writeFileSync(ROOMS_FILE, JSON.stringify(rooms, null, 2));
}

/** Resolve a file path to the Data Room it belongs to, or null */
function resolveRoom(filePath) {
  const rooms = loadRooms();
  const resolved = path.resolve(filePath);
  for (const room of rooms) {
    const roomResolved = path.resolve(room.path);
    if (resolved === roomResolved || resolved.startsWith(roomResolved + path.sep)) {
      return room;
    }
  }
  return null;
}

/** Check if a path is inside a closed Data Room */
function isPathBlocked(filePath) {
  const room = resolveRoom(filePath);
  return room ? room.closed : false;
}

// --- HTTP Handlers ---

function handleListRooms(req, res) {
  const rooms = loadRooms();
  const enriched = rooms.map(r => {
    let fileCount = 0;
    try {
      fileCount = fs.readdirSync(r.path, { withFileTypes: true }).filter(d => !d.name.startsWith('.')).length;
    } catch {}
    return { ...r, fileCount };
  });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: true, rooms: enriched }));
}

function handleAddRoom(req, res) {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    try {
      const { name, path: roomPath } = JSON.parse(body);
      if (!name || !roomPath) throw new Error('Name and path are required');
      const resolved = path.resolve(roomPath);
      if (!fs.existsSync(resolved)) throw new Error('Directory does not exist');
      const rooms = loadRooms();
      if (rooms.find(r => path.resolve(r.path) === resolved)) throw new Error('This directory is already a Data Room');
      const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      rooms.push({ id: id || `room-${Date.now()}`, name, path: resolved, isDefault: false, closed: false });
      saveRooms(rooms);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
  });
}

function handleCloseRoom(req, res) {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    try {
      const { id } = JSON.parse(body);
      const rooms = loadRooms();
      const room = rooms.find(r => r.id === id);
      if (!room) throw new Error('Room not found');
      room.closed = true;
      saveRooms(rooms);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: `Door closed on "${room.name}". All access blocked until re-opened.` }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
  });
}

function handleOpenRoom(req, res) {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    try {
      const { id } = JSON.parse(body);
      const rooms = loadRooms();
      const room = rooms.find(r => r.id === id);
      if (!room) throw new Error('Room not found');
      room.closed = false;
      saveRooms(rooms);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: `Door opened on "${room.name}". Access can be granted again.` }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message }));
    }
  });
}

function handleRoomHistory(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const roomId = url.searchParams.get('id');
  const rooms = loadRooms();
  const room = rooms.find(r => r.id === roomId);
  if (!room) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: false, error: 'Room not found' }));
  }
  const AUDIT_LOG = path.join(process.env.CROCBOX_LOG_DIR || path.join(__dirname, '..', 'logs'), 'crocbox-audit.jsonl');
  const entries = [];
  try {
    const lines = fs.readFileSync(AUDIT_LOG, 'utf8').trim().split('\n');
    const roomResolved = path.resolve(room.path);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.target && path.resolve(entry.target).startsWith(roomResolved)) {
          entries.push(entry);
        }
      } catch {}
    }
  } catch {}
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: true, room: room.name, history: entries.slice(-50) }));
}

function handleResolve(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const filePath = url.searchParams.get('path');
  if (!filePath) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: false, error: 'path parameter required' }));
  }
  const room = resolveRoom(filePath);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: true, room: room ? { id: room.id, name: room.name, closed: room.closed } : null }));
}

module.exports = {
  loadRooms,
  saveRooms,
  resolveRoom,
  isPathBlocked,
  handleListRooms,
  handleAddRoom,
  handleCloseRoom,
  handleOpenRoom,
  handleRoomHistory,
  handleResolve,
  DEFAULT_ROOMS,
  ROOMS_FILE,
};
