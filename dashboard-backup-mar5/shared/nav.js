/**
 * nav.js — CROCbox Shared Navigation
 *
 * Injects the top bar and nav bar into any page that includes this script.
 * Usage: <script src="/shared/nav.js"></script>
 * The script reads data-page attribute from <body> to highlight the active link.
 */
(function () {
  'use strict';

  const currentPage = document.body.dataset.page || '';

  const NAV_ITEMS = [
    { href: '/',              label: 'Home',           page: 'home' },
    { href: '/data.html',     label: 'My Data',        page: 'data' },
    { href: '/agents.html',   label: 'My Agents',      page: 'agents' },
    { href: '/permissions.html', label: 'My Permissions', page: 'permissions' },
    { href: '/activity.html', label: 'Activity',       page: 'activity' },
    { href: '/settings.html', label: '⚙',             page: 'settings' },
  ];

  // ── Top bar ────────────────────────────────────────
  function renderTopBar() {
    const topbar = document.createElement('div');
    topbar.className = 'topbar';
    topbar.innerHTML = `
      <a href="/" class="brand">
        <div class="logo">C</div>
        <span class="wordmark">CROCbox</span>
      </a>
      <div class="user-badge" id="navUserBadge">
        <span id="navUserName"></span> ▾
      </div>
    `;
    return topbar;
  }

  // ── Nav bar ────────────────────────────────────────
  function renderNavBar() {
    const nav = document.createElement('nav');
    nav.className = 'navbar';
    nav.innerHTML = NAV_ITEMS.map(item => {
      const cls = item.page === currentPage ? ' class="active"' : '';
      return `<a href="${item.href}"${cls}>${item.label}</a>`;
    }).join('');
    return nav;
  }

  // ── Inject into page ──────────────────────────────
  function inject() {
    const shell = document.querySelector('.shell');
    if (!shell) return;

    const topbar = renderTopBar();
    const navbar = renderNavBar();

    shell.prepend(navbar);
    shell.prepend(topbar);

    // Set user name from Supabase session if available
    updateUserBadge();
  }

  // ── Update user badge ─────────────────────────────
  async function updateUserBadge() {
    const nameEl = document.getElementById('navUserName');
    const badgeEl = document.getElementById('navUserBadge');
    if (!nameEl) return;

    try {
      // Wait for supabase.js to initialize
      if (window.crocboxSupabase) {
        const { data } = await window.crocboxSupabase.auth.getUser();
        if (data && data.user) {
          const meta = data.user.user_metadata || {};
          nameEl.textContent = meta.display_name || meta.name || data.user.email || 'User';
          badgeEl.style.display = 'flex';
          return;
        }
      }
    } catch {}

    // No session — hide badge or show generic
    nameEl.textContent = '';
    badgeEl.style.display = 'none';
  }

  // ── Sign out handler ──────────────────────────────
  document.addEventListener('click', async (e) => {
    if (e.target.closest('#navUserBadge')) {
      // Simple: click user badge → sign out (for MVP)
      if (window.crocboxSupabase && confirm('Sign out of CROCbox?')) {
        await window.crocboxSupabase.auth.signOut();
        window.location.href = '/first-run.html';
      }
    }
  });

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

  // Expose for other scripts
  window.crocboxNav = { updateUserBadge };
})();
