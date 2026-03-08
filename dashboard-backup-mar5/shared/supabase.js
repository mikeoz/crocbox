/**
 * supabase.js — CROCbox Supabase Client Initialization
 *
 * Fetches config from /api/config (which reads .env server-side),
 * then initializes the Supabase client.
 *
 * Usage: Include AFTER the Supabase CDN script:
 *   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js"></script>
 *   <script src="/shared/supabase.js"></script>
 *
 * Exposes: window.crocboxSupabase (the Supabase client)
 *          window.crocboxConfig  (the raw config object)
 *          window.crocboxReady   (Promise that resolves when client is ready)
 */
(function () {
  'use strict';

  let resolveReady;
  window.crocboxReady = new Promise(r => { resolveReady = r; });

  async function init() {
    try {
      // Fetch config from server (reads .env)
      const res = await fetch('/api/config');
      if (!res.ok) throw new Error('Config endpoint returned ' + res.status);
      const config = await res.json();

      window.crocboxConfig = config;

      if (!config.supabaseUrl || !config.supabaseAnonKey) {
        console.error('[SUPABASE] Missing SUPABASE_URL or SUPABASE_ANON_KEY in .env');
        resolveReady(false);
        return;
      }

      // Check that the Supabase library loaded from CDN
      if (!window.supabase || !window.supabase.createClient) {
        console.error('[SUPABASE] Supabase JS library not loaded. Check CDN script tag.');
        resolveReady(false);
        return;
      }

      // Initialize client
      window.crocboxSupabase = window.supabase.createClient(
        config.supabaseUrl,
        config.supabaseAnonKey
      );

      console.log('[SUPABASE] Client initialized for', config.supabaseUrl);
      resolveReady(true);

    } catch (err) {
      console.error('[SUPABASE] Initialization failed:', err.message);
      resolveReady(false);
    }
  }

  // Run immediately
  init();
})();
