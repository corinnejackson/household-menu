import APP_HTML from '../index.html';
import LOGIN_HTML from './login.html';
import MANIFEST from '../pwa/manifest.webmanifest';
import SERVICE_WORKER from '../pwa/sw.js';
import ICON_SVG from '../pwa/icon.svg';
import ICON_192 from '../pwa/icon-192.png';
import ICON_512 from '../pwa/icon-512.png';
import APPLE_TOUCH_ICON from '../pwa/apple-touch-icon.png';

const COOKIE_NAME = '__Host-planner_session';
const SESSION_DAYS = 180;
const MAX_FAILED_LOGINS = 10;
const FAILED_LOGIN_WINDOW_MS = 15 * 60 * 1000;
const AUTO_SNAPSHOT_GAP_MS = 30 * 60 * 1000;
const MAX_HISTORY_SNAPSHOTS = 50;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

const STATIC_KEYS = new Set([
  'dinners', 'breakfasts', 'stockedPantryItems', 'clearedAllergens', 'customGroceries', 'recentExtras',
  'babyBirthdate', 'selectedStageKey', 'stageOverride'
]);
const isValidKey = key => STATIC_KEYS.has(key) || /^(week|checks):\d{4}-\d{2}-\d{2}$/.test(key);

const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'X-Robots-Tag': 'noindex, nofollow',
  'Strict-Transport-Security': 'max-age=31536000'
};

const PUBLIC_FILES = {
  '/pwa/manifest.webmanifest': [MANIFEST, 'application/manifest+json'],
  '/pwa/icon.svg': [ICON_SVG, 'image/svg+xml'],
  '/pwa/icon-192.png': [ICON_192, 'image/png'],
  '/pwa/icon-512.png': [ICON_512, 'image/png'],
  '/pwa/apple-touch-icon.png': [APPLE_TOUCH_ICON, 'image/png']
};

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (err) {
      console.error(err);
      return json({ error: 'Server error' }, 500);
    }
  }
};

async function handle(request, env) {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;

  if (PUBLIC_FILES[pathname]) {
    const [body, type] = PUBLIC_FILES[pathname];
    return new Response(body, { headers: { 'Content-Type': type, 'Cache-Control': 'public, max-age=86400', ...SECURITY_HEADERS } });
  }
  if (pathname === '/sw.js') {
    return new Response(SERVICE_WORKER, { headers: { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS } });
  }

  // Browsers always send Origin on cross-site POST/PUT/DELETE; reject those outright
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) return json({ error: 'Bad origin' }, 403);
  }

  if (pathname === '/login') {
    if (method === 'POST') return handleLogin(request, env);
    if (await sessionAccount(request, env)) return redirect('/');
    return loginPage();
  }
  if (pathname === '/logout' && method === 'POST') {
    return redirect('/login', { 'Set-Cookie': `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
  }

  const account = await sessionAccount(request, env);

  if (pathname === '/' || pathname === '/index.html') {
    if (!account) return redirect('/login');
    return appPage(env, account);
  }

  if (pathname.startsWith('/api/')) {
    if (!account) return json({ error: 'Not signed in' }, 401);
    return handleApi(request, env, url, account.id);
  }

  return new Response('Not found', { status: 404, headers: SECURITY_HEADERS });
}

// ---------- Pages ----------

async function appPage(env, account) {
  const { state, version } = await loadState(env, account.id);
  // Embed the current state so the first paint already shows synced data
  const boot = JSON.stringify({
    version,
    state,
    servedAt: Date.now(),
    account: { id: account.id, baby: !!account.baby }
  }).replace(/</g, '\\u003c');
  const html = APP_HTML.replace('<head>', `<head>\n  <script>window.__PLANNER_BOOT__ = ${boot};</script>`);
  const token = await createSessionToken(env, account);
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Set-Cookie': sessionCookie(token),
      ...SECURITY_HEADERS
    }
  });
}

function loginPage(error = '', status = 200) {
  const html = LOGIN_HTML.replace('{{ERROR}}', error ? `<p class="error" role="alert">${error}</p>` : '');
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS }
  });
}

// ---------- Auth ----------

async function handleLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  const now = Date.now();

  const attempt = await env.DB.prepare('SELECT fails, first_fail_at FROM login_attempts WHERE ip = ?').bind(ip).first();
  const windowActive = attempt && now - attempt.first_fail_at < FAILED_LOGIN_WINDOW_MS;
  if (windowActive && attempt.fails >= MAX_FAILED_LOGINS) {
    const minutes = Math.ceil((attempt.first_fail_at + FAILED_LOGIN_WINDOW_MS - now) / 60000);
    return loginPage(`Too many attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`, 429);
  }

  let username = '';
  let password = '';
  try {
    const form = await request.formData();
    username = String(form.get('username') || '').trim().toLowerCase();
    password = String(form.get('password') || '');
  } catch {
    return loginPage('Something went wrong. Please try again.', 400);
  }

  const account = await env.DB.prepare('SELECT id, password_secret FROM accounts WHERE username = ?').bind(username).first();
  if (!env.SESSION_SECRET || (account && !env[account.password_secret])) {
    return loginPage('The server is missing its password configuration.', 500);
  }

  if (account && await safeEqual(password, env[account.password_secret])) {
    await env.DB.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run();
    const token = await createSessionToken(env, account);
    return redirect('/', { 'Set-Cookie': sessionCookie(token) });
  }

  await env.DB.prepare(
    `INSERT INTO login_attempts (ip, fails, first_fail_at) VALUES (?1, 1, ?2)
     ON CONFLICT(ip) DO UPDATE SET
       fails = CASE WHEN ?2 - first_fail_at >= ?3 THEN 1 ELSE fails + 1 END,
       first_fail_at = CASE WHEN ?2 - first_fail_at >= ?3 THEN ?2 ELSE first_fail_at END`
  ).bind(ip, now, FAILED_LOGIN_WINDOW_MS).run();
  return loginPage('That username or password isn\'t right.', 401);
}

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b))
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

// Keyed on the account's password too, so changing it signs that account's devices out
async function hmacKey(env, password) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(`${env.SESSION_SECRET}|${password}`),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function createSessionToken(env, account) {
  const expires = Date.now() + SESSION_DAYS * 86400 * 1000;
  const key = await hmacKey(env, env[account.password_secret]);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`v2.${account.id}.${expires}`));
  return `${account.id}.${expires}.${b64url(sig)}`;
}

function sessionCookie(token) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

// Returns the signed-in account, or null
async function sessionAccount(request, env) {
  if (!env.SESSION_SECRET) return null;
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  if (!match) return null;
  const parts = match[1].split('.');
  // Cookies from before accounts existed ("expires.sig", signed "v1.expires") belong to account 1.
  // The app page swaps them for a new cookie, so this can go once they've expired (March 2027).
  const [id, expires, sig] = parts.length === 2 ? ['1', ...parts] : parts;
  const message = parts.length === 2 ? `v1.${expires}` : `v2.${id}.${expires}`;
  if (!/^\d+$/.test(id || '') || !expires || !sig || Number(expires) < Date.now()) return null;
  const account = await env.DB.prepare('SELECT id, password_secret, baby FROM accounts WHERE id = ?').bind(Number(id)).first();
  const password = account && env[account.password_secret];
  if (!password) return null;
  try {
    const valid = await crypto.subtle.verify('HMAC', await hmacKey(env, password), fromB64url(sig), new TextEncoder().encode(message));
    return valid ? account : null;
  } catch {
    return null;
  }
}

// ---------- API ----------

async function handleApi(request, env, url, account) {
  const { pathname } = url;
  const method = request.method;

  if (pathname === '/api/state' && method === 'GET') {
    const since = Number(url.searchParams.get('since'));
    const version = await currentVersion(env, account);
    if (url.searchParams.has('since') && since === version) return json({ version, unchanged: true });
    return json(await loadState(env, account));
  }

  if (pathname === '/api/state' && method === 'PUT') {
    const body = await readJson(request);
    if (!body || typeof body.changes !== 'object' || body.changes === null) return json({ error: 'Invalid body' }, 400);
    const keys = Object.keys(body.changes);
    if (keys.some(k => !isValidKey(k))) return json({ error: 'Unknown key' }, 400);
    const label = typeof body.snapshot === 'string' ? body.snapshot.slice(0, 120) : null;
    const week = typeof body.week === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(body.week) ? body.week : null;
    return json(await applyChanges(env, account, body.changes, label, week));
  }

  if (pathname === '/api/snapshots' && method === 'GET') {
    const { results } = await env.DB.prepare(
      'SELECT id, created_at, kind, label, week, summary FROM snapshots WHERE account = ? ORDER BY id DESC LIMIT 200'
    ).bind(account).all();
    return json({ snapshots: results.map(r => ({ ...r, summary: JSON.parse(r.summary) })) });
  }

  if (pathname === '/api/snapshots' && method === 'POST') {
    const body = await readJson(request);
    const label = typeof body?.label === 'string' ? body.label.trim().slice(0, 120) : '';
    if (!label) return json({ error: 'A name is required' }, 400);
    const week = typeof body.week === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(body.week) ? body.week : null;
    const { state } = await loadState(env, account);
    const row = await snapshotStatement(env, account, 'saved', label, week, state, Date.now()).first();
    return json({ id: row.id });
  }

  const snapMatch = pathname.match(/^\/api\/snapshots\/(\d+)$/);
  if (snapMatch && method === 'GET') {
    const row = await env.DB.prepare('SELECT id, created_at, kind, label, week, data FROM snapshots WHERE id = ? AND account = ?').bind(Number(snapMatch[1]), account).first();
    if (!row) return json({ error: 'Not found' }, 404);
    return json({ ...row, data: JSON.parse(row.data) });
  }
  if (snapMatch && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM snapshots WHERE id = ? AND account = ?').bind(Number(snapMatch[1]), account).run();
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

async function readJson(request) {
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > MAX_BODY_BYTES) return null;
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function currentVersion(env, account) {
  return (await env.DB.prepare('SELECT version FROM meta WHERE account = ?').bind(account).first('version')) || 0;
}

async function loadState(env, account) {
  const [rows, version] = await Promise.all([
    env.DB.prepare('SELECT key, value FROM state WHERE account = ?').bind(account).all(),
    currentVersion(env, account)
  ]);
  const state = {};
  for (const r of rows.results) state[r.key] = JSON.parse(r.value);
  return { state, version };
}

async function applyChanges(env, account, changes, label, week) {
  const now = Date.now();
  const { state, version } = await loadState(env, account);
  const statements = [];

  // Checkpoint the pre-change state before destructive actions and at the start of each editing session
  if (version > 0) {
    const lastSnapshotAt = await env.DB.prepare('SELECT MAX(created_at) AS t FROM snapshots WHERE account = ?').bind(account).first('t');
    if (label) {
      statements.push(snapshotStatement(env, account, 'undo', label, week, state, now));
    } else if (!lastSnapshotAt || now - lastSnapshotAt > AUTO_SNAPSHOT_GAP_MS) {
      statements.push(snapshotStatement(env, account, 'auto', 'Automatic checkpoint', week, state, now));
    }
  }

  for (const [key, value] of Object.entries(changes)) {
    if (value === null) {
      statements.push(env.DB.prepare('DELETE FROM state WHERE account = ? AND key = ?').bind(account, key));
    } else {
      statements.push(env.DB.prepare(
        `INSERT INTO state (account, key, value, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
      ).bind(account, key, JSON.stringify(value), now));
    }
  }

  statements.push(env.DB.prepare(
    `DELETE FROM snapshots WHERE account = ?1 AND kind != 'saved' AND id NOT IN
       (SELECT id FROM snapshots WHERE account = ?1 AND kind != 'saved' ORDER BY id DESC LIMIT ?2)`
  ).bind(account, MAX_HISTORY_SNAPSHOTS));
  statements.push(env.DB.prepare(
    'INSERT INTO meta (account, version) VALUES (?, 1) ON CONFLICT(account) DO UPDATE SET version = version + 1 RETURNING version'
  ).bind(account));

  const results = await env.DB.batch(statements);
  return { version: results[results.length - 1].results[0].version };
}

function snapshotStatement(env, account, kind, label, week, state, now) {
  return env.DB.prepare(
    'INSERT INTO snapshots (account, created_at, kind, label, week, summary, data) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id'
  ).bind(account, now, kind, label, week, JSON.stringify(summarize(state)), JSON.stringify(state));
}

// Dinner titles for the most recent planned weeks, so the History list can show what each entry contains
function summarize(state) {
  const dinners = Array.isArray(state.dinners) ? state.dinners : [];
  const titleOf = id => dinners.find(d => d.id === id)?.title || null;
  const weeks = {};
  Object.keys(state)
    .filter(k => k.startsWith('week:'))
    .sort()
    .reverse()
    .forEach(k => {
      const plan = state[k] || {};
      const titles = DAYS.map(day => titleOf(plan[day]?.dinner));
      if (titles.some(Boolean) && Object.keys(weeks).length < 4) weeks[k.slice(5)] = titles;
    });
  return {
    dinnerCount: dinners.length,
    breakfastCount: Array.isArray(state.breakfasts) ? state.breakfasts.length : 0,
    weeks
  };
}

// ---------- Helpers ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...SECURITY_HEADERS }
  });
}

function redirect(location, extraHeaders = {}) {
  return new Response(null, { status: 303, headers: { Location: location, 'Cache-Control': 'no-store', ...extraHeaders, ...SECURITY_HEADERS } });
}
