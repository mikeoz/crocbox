/**
 * auth.js — CROCbox Auth Guard
 *
 * Checks for an active Supabase session. If no session,
 * redirects to /first-run.html.
 *
 * Usage: Include AFTER supabase.js:
 *   <script src="/shared/auth.js"></script>
 *
 * Pages that do NOT require auth (first-run.html) should NOT include this script.
 */
(function () {
  'use strict';

  async function checkAuth() {
    // Wait for Supabase client to be ready
    const ready = await window.crocboxReady;

    if (!ready || !window.crocboxSupabase) {
      // Supabase not configured — allow access for development/demo
      console.warn('[AUTH] Supabase not available. Running in local-only mode.');
      document.body.classList.add('auth-ready');
      document.body.classList.add('auth-local');
      return;
    }

    try {
      const { data: { session } } = await window.crocboxSupabase.auth.getSession();

      if (!session) {
        // No active session — redirect to first run
        console.log('[AUTH] No session. Redirecting to first-run.');
        window.location.href = '/first-run.html';
        return;
      }

      // Session exists — user is logged in
      console.log('[AUTH] Session active for', session.user.email);
      document.body.classList.add('auth-ready');

      // Update nav if available
      if (window.crocboxNav && window.crocboxNav.updateUserBadge) {
        window.crocboxNav.updateUserBadge();
      }

    } catch (err) {
      console.error('[AUTH] Session check failed:', err.message);
      // Allow access in case of error — don't lock user out
      document.body.classList.add('auth-ready');
      document.body.classList.add('auth-error');
    }
  }

  // Run on load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkAuth);
  } else {
    checkAuth();
  }
})();
