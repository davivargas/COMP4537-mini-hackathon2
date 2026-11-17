'use strict';

// One script for all four pages. <body data-page="..."> says which page this is.
// The JWT lives in an HttpOnly cookie, so this code never sees it: it only
// asks the API and reacts to 200 (logged in) or 401 (not logged in).
// All server data is written with textContent, never innerHTML, so nothing
// the server returns can run as script.

(function main() {
  const { TEAM, API_URL } = window.APP_CONFIG;
  const LOGIN_PAGE = 'index.html';
  const ADMIN_PAGE = 'admin.html';

  const page = document.body.dataset.page;
  const byId = (id) => document.getElementById(id);

  const REQUEST_TIMEOUT_MS = 8000;

  function api(path, options) {
    // credentials: 'include' makes the browser send and store the cookie even
    // though the API is on a different origin. The timeout turns a hung
    // server into an error message instead of an endless "Loading".
    return fetch(API_URL + path, {
      credentials: 'include',
      cache: 'no-store',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      ...options,
    });
  }

  // The Back button can restore a page from the browser's memory without
  // running this script again. After a logout that would put the secret back
  // on screen, so a restored page is reloaded and re-checked with the API.
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) window.location.reload();
  });

  // Team number wherever the page asks for it.
  for (const element of document.querySelectorAll('[data-team]')) element.textContent = TEAM;

  function showStatus(message) {
    const status = byId('status');
    status.textContent = message;
    status.hidden = false;
  }

  // ---------- Login page ----------

  async function initLogin() {
    const form = byId('login-form');
    const error = byId('error');
    const button = byId('login-button');

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      error.hidden = true;
      button.disabled = true;
      try {
        const response = await api('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: byId('username').value, password: byId('password').value }),
        });
        if (response.ok) {
          window.location.replace(ADMIN_PAGE);
          return;
        }
        if (response.status === 401) error.textContent = 'Invalid username or password.';
        else if (response.status === 429) error.textContent = 'Too many attempts. Wait a few seconds and try again.';
        else error.textContent = 'Login failed. Please try again.';
      } catch {
        error.textContent = 'Cannot reach the server. Please try again.';
      }
      error.hidden = false;
      button.disabled = false;
    });

    // Already logged in? Skip the form.
    try {
      const response = await api('/api/page1');
      if (response.ok) window.location.replace(ADMIN_PAGE);
    } catch {
      // Server unreachable: just leave the form on screen.
    }
  }

  // ---------- Protected pages ----------

  function initNavigation() {
    byId('logout').addEventListener('click', async () => {
      try {
        await api('/api/logout', { method: 'POST' });
      } catch {
        // Even if the request fails we leave the protected area.
      }
      window.location.replace(LOGIN_PAGE);
    });
  }

  /** Fetch protected data. Sends the visitor to the login page on 401. */
  async function loadProtected(path) {
    let response;
    try {
      response = await api(path);
    } catch {
      showStatus('Cannot reach the server. Refresh to try again.');
      return null;
    }
    if (response.status === 401) {
      window.location.replace(LOGIN_PAGE);
      return null;
    }
    if (!response.ok) {
      showStatus('The server is busy. Refresh to try again.');
      return null;
    }
    return response.json();
  }

  function reveal() {
    byId('status').hidden = true;
    byId('content').hidden = false;
  }

  async function initAdmin() {
    initNavigation();
    const data = await loadProtected('/api/admin');
    if (!data) return;
    const welcome = byId('welcome');
    const render = () => {
      welcome.textContent = `Welcome to Team ${TEAM}, Secret: "${data.secret}", Time: ${new Date().toLocaleString()}`;
    };
    render();
    setInterval(render, 1000); // keep the browser clock current
    document.title = `Team ${TEAM} · Admin Landing Page`;
    reveal();
  }

  async function initContentPage(path) {
    initNavigation();
    const data = await loadProtected(path);
    if (!data) return;
    byId('title').textContent = data.title;
    reveal();
  }

  const pages = {
    login: initLogin,
    admin: initAdmin,
    page1: () => initContentPage('/api/page1'),
    page2: () => initContentPage('/api/page2'),
  };
  pages[page]();
})();
