/**
 * CROCbox v0.8 — Electron Preload Script
 * 
 * Phase 1: Minimal — just marks the window as CROCbox.
 * Phase 4 will add: consent IPC bridge, WebSocket URL override.
 * 
 * @see OPN_ENG_v08-Architecture_15MAR26_v1, Section 3.3
 */

const { contextBridge } = require('electron');

// Expose CROCbox identity to the renderer
contextBridge.exposeInMainWorld('crocbox', {
  version: '0.8.0',
  phase: 'soft-launch',
  isCROCbox: true
});

console.log('[CROCbox] Preload script loaded');
