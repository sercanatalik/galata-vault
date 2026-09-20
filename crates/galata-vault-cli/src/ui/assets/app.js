// gv ui's page script. It never sees a key or a token: it asks gv ui to
// reveal, copy or change something, and shows the answer. A revealed value
// leaves the document after a few seconds; a copied one never arrives here.
'use strict';

(function theme() {
  let stored = null;
  try { stored = localStorage.getItem('gv-theme'); } catch (_) { /* no storage */ }
  const dark = stored ? stored === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.classList.toggle('dark', dark);
})();

const HEADERS = { 'X-GV-UI': '1', 'Content-Type': 'application/json' };
const MASK = '••••••••••••';
let pinger = null;

class Refused extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

function $(sel, root) { return (root || document).querySelector(sel); }
function $$(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

async function api(path, body, method) {
  const post = (method || 'POST') === 'POST';
  let r;
  try {
    r = await fetch(path, {
      method: post ? 'POST' : 'GET',
      headers: post ? HEADERS : { 'X-GV-UI': '1' },
      body: post ? JSON.stringify(body || {}) : undefined,
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch (_) {
    show('stopped');
    throw new Refused('gv ui is not answering', 0);
  }
  if (r.status === 401) { show('locked'); throw new Refused('locked', 401); }
  let j = {};
  try { j = await r.json(); } catch (_) { /* empty body */ }
  if (!r.ok) throw new Refused(j.message || ('HTTP ' + r.status), r.status);
  return j;
}

// Locked or stopped: keep nothing that was on screen.
function show(which) {
  const main = $('main.main');
  if (main) main.replaceChildren();
  $$('[data-modal]').forEach(m => { m.hidden = true; });
  const o = $('[data-overlay="' + which + '"]');
  if (o) o.hidden = false;
  if (pinger) clearInterval(pinger);
}

let toastTimer = null;
function toast(title, detail) {
  const t = $('[data-toast]');
  if (!t) return;
  const b = document.createElement('div');
  b.className = 'b';
  b.textContent = title;
  const d = document.createElement('div');
  d.className = 'muted small';
  d.textContent = detail || '';
  t.replaceChildren(b, d);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 6000);
}

function openModal(name) {
  const m = $('[data-modal="' + name + '"]');
  if (!m) return null;
  m.hidden = false;
  const first = $('input:not([type=hidden]), textarea', m);
  if (first) first.focus();
  return m;
}

// A plain question, for changes the terminal does not guard.
function ask(text) {
  const m = openModal('ask');
  $('[data-ask-text]', m).textContent = text;
  return new Promise(resolve => {
    const done = v => { m.hidden = true; resolve(v); };
    $('[data-ask-ok]', m).onclick = () => done(true);
    $$('[data-close]', m).forEach(b => { b.onclick = () => done(false); });
  });
}

// One value, shown for a few seconds, then gone from the document.
async function reveal(btn) {
  if (btn.hideNow) { btn.hideNow(); return; }
  const scope = btn.closest('.trow, .ver');
  const cell = $('[data-value]', scope);
  const count = $('[data-countdown]', scope);
  let j;
  try { j = await api('/api/reveal', JSON.parse(btn.dataset.reveal)); } catch (e) {
    if (e.status) toast('not revealed', e.message);
    return;
  }
  cell.textContent = j.value;
  cell.classList.remove('mask');
  btn.classList.add('on');
  let left = j.hide_after;
  j = null;
  const paint = () => { if (count) count.textContent = 'hides in ' + left + ' s'; };
  const timer = setInterval(() => { left -= 1; if (left <= 0) btn.hideNow(); else paint(); }, 1000);
  paint();
  btn.hideNow = () => {
    clearInterval(timer);
    cell.textContent = MASK;
    cell.classList.add('mask');
    if (count) count.textContent = '';
    btn.classList.remove('on');
    btn.hideNow = null;
  };
}

async function copy(btn) {
  const body = JSON.parse(btn.dataset.copy);
  try {
    const j = await api('/api/copy', body);
    toast('copied ' + body.name, 'the clipboard clears in ' + j.clears_in + ' s. the value went from gv ui to the clipboard, never through this page.');
  } catch (e) {
    if (e.status) toast('not copied', e.message);
  }
}

async function action(btn) {
  if (btn.dataset.ask && !(await ask(btn.dataset.ask))) return;
  try {
    await api(btn.dataset.api, JSON.parse(btn.dataset.body));
    location.reload();
  } catch (e) {
    if (e.status) toast('refused', e.message);
  }
}

async function submitForm(form) {
  const body = Object.fromEntries(new FormData(form).entries());
  const err = $('[data-form-error]', form);
  const button = $('button[type=submit]', form);
  if (button) button.disabled = true;
  try {
    await api(form.dataset.form, body);
    location.reload();
  } catch (e) {
    if (err) { err.textContent = e.message; err.hidden = false; } else if (e.status) toast('refused', e.message);
  } finally {
    if (button) button.disabled = false;
    // Never leave a typed value in the page.
    $$('textarea[name=value]', form).forEach(t => { t.value = ''; });
  }
}

// Ask gv ui, which asks the terminal; show the code and wait for the answer.
async function confirmFlow(path, body, title) {
  let j;
  try { j = await api(path, body); } catch (e) {
    if (e.status) toast('not asked', e.message);
    return;
  }
  const m = openModal('confirm');
  const state = $('[data-confirm-state]', m);
  const dot = $('[data-confirm-dot]', m);
  const box = $('[data-handover-box]', m);
  $('[data-confirm-title]', m).textContent = title;
  $('[data-confirm-code]', m).textContent = j.code;
  state.textContent = 'waiting for the terminal';
  dot.className = 'dot amber pulse';
  box.hidden = true;
  let finished = false;
  let taken = false;
  const poll = setInterval(async () => {
    let s;
    try { s = await api('/api/confirm/' + j.confirm, null, 'GET'); } catch (_) { clearInterval(poll); return; }
    if (s.state === 'waiting') return;
    clearInterval(poll);
    finished = true;
    state.textContent = s.message;
    dot.className = 'dot ' + (s.state === 'done' || s.state === 'handover' ? 'ok' : 'bad');
    if (s.state === 'handover') box.hidden = false;
  }, 1000);
  $$('[data-handover]', m).forEach(b => {
    b.onclick = async () => {
      const how = b.dataset.handover;
      const path = $('[data-handover-path]', m).value;
      try {
        const r = await api('/api/handover/' + how, { confirm: j.confirm, path });
        taken = true;
        box.hidden = true;
        state.textContent = how === 'copy'
          ? 'token copied: the clipboard clears in ' + r.clears_in + ' s'
          : 'token saved to ' + r.saved + ' (mode 0600)';
      } catch (e) {
        if (e.status) toast('not handed over', e.message);
      }
    };
  });
  $$('[data-close]', m).forEach(b => {
    b.onclick = async () => {
      clearInterval(poll);
      if (!box.hidden && !taken) {
        try { await api('/api/handover/discard', { confirm: j.confirm }); } catch (_) { /* gone */ }
      }
      m.hidden = true;
      if (finished) location.reload();
    };
  });
}

async function boot() {
  const m = /[#&]c=([0-9a-f]+)/.exec(location.hash);
  // The code leaves the address bar before anything else happens.
  history.replaceState(null, '', '/');
  const state = s => $$('[data-state]').forEach(c => { c.hidden = c.dataset.state !== s; });
  if (!m) { state('nolink'); return; }
  try {
    const r = await fetch('/session', {
      method: 'POST', headers: HEADERS, body: JSON.stringify({ code: m[1] }), credentials: 'same-origin',
    });
    if (r.ok) { location.replace('/projects'); return; }
  } catch (_) { /* fall through */ }
  state('used');
}

document.addEventListener('DOMContentLoaded', () => {
  const body = document.body;
  if (body.hasAttribute('data-boot')) { boot(); return; }
  if (!body.hasAttribute('data-app')) return;

  pinger = setInterval(async () => {
    try {
      const r = await fetch('/api/ping', { credentials: 'same-origin', cache: 'no-store' });
      if (r.status === 401) show('locked');
    } catch (_) {
      show('stopped');
    }
  }, 5000);

  document.addEventListener('click', ev => {
    const t = ev.target.closest('button, a');
    if (!t || t.disabled) return;
    if (t.matches('[data-reveal]')) { ev.preventDefault(); reveal(t); }
    else if (t.matches('[data-copy]')) { ev.preventDefault(); copy(t); }
    else if (t.matches('[data-api]')) { ev.preventDefault(); action(t); }
    else if (t.matches('[data-confirm-api]')) {
      ev.preventDefault();
      confirmFlow(t.dataset.confirmApi, JSON.parse(t.dataset.body), t.dataset.title);
    }
    else if (t.matches('[data-open]')) { ev.preventDefault(); openModal(t.dataset.open); }
    else if (t.matches('[data-lock]')) {
      ev.preventDefault();
      api('/api/lock').then(() => show('locked'), () => show('locked'));
    }
    else if (t.matches('[data-theme-toggle]')) {
      const dark = !document.documentElement.classList.contains('dark');
      document.documentElement.classList.toggle('dark', dark);
      try { localStorage.setItem('gv-theme', dark ? 'dark' : 'light'); } catch (_) { /* no storage */ }
    }
    else if (t.matches('[data-close]') && !t.onclick) {
      const m = t.closest('[data-modal]');
      if (m) m.hidden = true;
    }
  });

  document.addEventListener('submit', ev => {
    const f = ev.target;
    if (f.dataset.form) { ev.preventDefault(); submitForm(f); }
    else if (f.dataset.confirmForm) {
      ev.preventDefault();
      const b = Object.fromEntries(new FormData(f).entries());
      confirmFlow(f.dataset.confirmForm, b, 'Mint a ' + b.scope + ' token for ' + b.env);
    }
  });

  document.addEventListener('keydown', ev => {
    if (ev.key !== 'Escape') return;
    const open = $$('[data-modal]').find(m => !m.hidden);
    if (open) { const c = $('[data-close]', open); if (c) c.click(); }
  });
});
