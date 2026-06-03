import './style.css';
import { Status, Disconnect, PickCredential, Connect, Reconnect, Profile, ImportProfileBundle } from '../wailsjs/go/main/App';
import { WindowSetSize, WindowGetSize } from '../wailsjs/runtime/runtime';

// Two screens in one popover: the main status view and the credential-import
// sheet. The main view mirrors the daemon (poll Status() every ~1.5s and render
// from it). Credentials are picked file-by-file via Go (PickCredential opens a
// native dialog and keeps the PEM bytes in the backend); the sheet only sends
// the non-secret form (server + options) on Save.

const POLL_MS = 1500;

const LABELS = {
  disconnected: 'Not connected',
  connecting:   'Connecting…',
  connected:    'Connected',
  reconnecting: 'Reconnecting…',
  failed:       'Connection failed',
};

const MINI_SPIN =
  '<svg aria-hidden="true" focusable="false" class="mini-spin" viewBox="0 0 24 24" fill="none">' +
  '<path d="M12 3a9 9 0 0 1 6.4 2.6" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>';

const el = (id) => document.getElementById(id);

const tray = el('tray');
const viewMain = el('view-main');
const viewImport = el('view-import');

// main-screen refs
const stateLabel = el('state-label');
const stateSub = el('state-sub');
const profileBtn = el('profile');
const profileName = el('profile-name');
const timer = el('timer');
const notice = el('notice');
const noticeTitle = el('notice-title');
const noticeDetail = el('notice-detail');
const actionBtn = el('action-btn');

// import-screen refs
const impServer = el('imp-server');
const impSni = el('imp-sni');
const impMtu = el('imp-mtu');
const impTun = el('imp-tun');
const impBundle = el('imp-bundle');
const impSave = el('imp-save');
const impCancel = el('imp-cancel');
const impBack = el('imp-back');
const impError = el('imp-error');
const impErrorDetail = el('imp-error-detail');

const credEls = {
  ca:   { row: el('cred-ca'),   hint: el('cred-ca-hint'),   action: el('cred-ca-action') },
  cert: { row: el('cred-cert'), hint: el('cred-cert-hint'), action: el('cred-cert-action') },
  key:  { row: el('cred-key'),  hint: el('cred-key-hint'),  action: el('cred-key-action') },
};
// remember each row's default hint so clearing a slot restores it
for (const r of Object.keys(credEls)) credEls[r].defaultHint = credEls[r].hint.textContent;

let sinceUnix = 0;          // session-timer origin (0 = not connected)
let hasProfile = false;     // a complete draft is staged (Connect vs Import)
let profileServer = '';     // staged server, for the disconnected sub-line / chip
let actionError = '';       // an immediate Connect failure to surface (e.g. helper down)
const credLoaded = { ca: false, cert: false, key: false };
let currentView = 'main';

// --- helpers -------------------------------------------------------------

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function hostOf(server) {
  return String(server).replace(/:\d+$/, '');
}

// Size the native window so the visible view's *content* fits its client area.
// WindowSetSize sets the OUTER window size, so on Windows (native title bar +
// borders) we add the real frame: the difference between the outer window
// (WindowGetSize) and the webview viewport (innerWidth/innerHeight). WebView2
// does not expose the OS frame via window.outerHeight, so that delta would be 0
// — going through the Wails Go side is what makes this correct and DPI-safe. On
// macOS the title bar is hidden, so the frame is ~0 and this just fits content.
// No-op outside Wails (e.g. a headless render), where the runtime isn't injected.
function resizeToContent() {
  requestAnimationFrame(async () => {
    const h = Math.ceil(tray.getBoundingClientRect().height);
    if (h <= 0) return;
    let frameW = 0, frameH = 0;
    try {
      const outer = await WindowGetSize();
      frameW = Math.max(0, outer.w - window.innerWidth);
      frameH = Math.max(0, outer.h - window.innerHeight);
    } catch (_) { /* not running under Wails */ }
    try { WindowSetSize(360 + frameW, h + frameH); } catch (_) { /* not running under Wails */ }
  });
}

function showView(name) {
  currentView = name;
  viewMain.classList.toggle('is-hidden', name !== 'main');
  viewImport.classList.toggle('is-hidden', name !== 'import');
  resizeToContent();
}

function updateTimer() {
  if (!sinceUnix) return;
  const s = Math.max(0, Math.floor(Date.now() / 1000) - sinceUnix);
  const pad = (n) => String(n).padStart(2, '0');
  timer.textContent = `${pad(Math.floor(s / 3600))}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
}

// --- main screen ---------------------------------------------------------

async function doDisconnect() {
  actionBtn.disabled = true;
  try {
    await Disconnect();
  } catch (e) {
    console.error('disconnect failed:', e);
  }
  poll();
}

async function doConnect() {
  actionError = '';
  actionBtn.disabled = true;
  try {
    await Reconnect();
  } catch (e) {
    // Surface it (e.g. "helper not running") instead of silently staying on
    // "Not connected"; render() shows it and the next poll keeps it until the
    // tunnel actually starts.
    actionError = e && e.message ? e.message : String(e);
  }
  poll();
}

function applyAction(state) {
  actionBtn.className = 'btn';
  actionBtn.disabled = false;
  actionBtn.onclick = null;
  actionBtn.textContent = '';

  switch (state) {
    case 'connecting':
      actionBtn.classList.add('btn--quiet');
      actionBtn.innerHTML = MINI_SPIN + 'Cancel';
      actionBtn.onclick = doDisconnect;
      break;
    case 'connected':
    case 'reconnecting':
      actionBtn.classList.add('btn--quiet', 'btn--danger');
      actionBtn.textContent = 'Disconnect';
      actionBtn.onclick = doDisconnect;
      break;
    case 'failed':
      actionBtn.classList.add('btn--primary');
      if (hasProfile) {
        actionBtn.textContent = 'Try again';
        actionBtn.onclick = doConnect;
      } else {
        actionBtn.textContent = 'Import a profile';
        actionBtn.onclick = openImport;
      }
      break;
    default: // disconnected
      actionBtn.classList.add('btn--primary');
      if (hasProfile) {
        actionBtn.textContent = 'Connect';
        actionBtn.onclick = doConnect;
      } else {
        actionBtn.textContent = 'Import a profile';
        actionBtn.onclick = openImport;
      }
  }
}

function render(st, reachable) {
  const state = reachable ? st.state : 'disconnected';
  tray.setAttribute('data-state', state);
  stateLabel.textContent = LABELS[state] || state;

  let subHTML = '';
  if (!reachable) {
    subHTML = 'Background helper not running';
  } else if (state === 'connecting' || state === 'connected') {
    subHTML = st.server ? `<span class="server">${escapeHTML(st.server)}</span>` : '';
  } else if (state === 'reconnecting') {
    subHTML = 'Connection dropped · retrying';
  } else if (state === 'disconnected') {
    subHTML = hasProfile
      ? `<span class="server">${escapeHTML(profileServer)}</span>`
      : 'Import a profile to connect';
  }
  stateSub.innerHTML = subHTML;
  stateSub.classList.toggle('is-hidden', subHTML === '');

  const chip = (reachable && st.server) ? hostOf(st.server) : (hasProfile ? hostOf(profileServer) : 'vpn.io');
  profileName.textContent = chip;

  if (reachable && state === 'connected' && st.sinceUnix > 0) {
    sinceUnix = st.sinceUnix;
    timer.classList.remove('is-hidden');
    updateTimer();
  } else {
    sinceUnix = 0;
    timer.classList.add('is-hidden');
  }

  if (reachable && state === 'failed') {
    noticeTitle.textContent = 'Connection failed';
    noticeDetail.textContent = st.lastError || 'The connection could not be established.';
    notice.classList.remove('is-hidden');
  } else if (actionError) {
    noticeTitle.textContent = "Couldn't connect";
    noticeDetail.textContent = actionError;
    notice.classList.remove('is-hidden');
  } else {
    notice.classList.add('is-hidden');
  }
  // Drop the transient action error once the tunnel is actually progressing.
  if (state === 'connecting' || state === 'connected' || state === 'reconnecting') actionError = '';

  applyAction(state);
  resizeToContent();
}

let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  try {
    try {
      const p = await Profile();
      hasProfile = p.hasProfile;
      profileServer = p.server;
    } catch (_) { /* Profile is local; ignore the rare failure */ }

    try {
      const st = await Status();
      render(st, true);
    } catch (_) {
      render({ state: 'disconnected' }, false);
    }
  } finally {
    polling = false;
  }
}

// --- import sheet --------------------------------------------------------

function showImportError(e) {
  impErrorDetail.textContent = e && e.message ? e.message : String(e);
  impError.classList.remove('is-hidden');
  resizeToContent();
}
function hideImportError() {
  impError.classList.add('is-hidden');
}

function setCred(role, loaded, fileName) {
  credLoaded[role] = loaded;
  const c = credEls[role];
  c.row.classList.toggle('is-set', loaded);
  c.hint.textContent = loaded ? `${fileName} · loaded` : c.defaultHint;
  c.action.textContent = loaded ? 'Change' : 'Choose…';
  updateSaveEnabled();
}

function updateSaveEnabled() {
  impSave.disabled = !(impServer.value.trim() && credLoaded.ca && credLoaded.cert && credLoaded.key);
}

async function pick(role) {
  hideImportError();
  try {
    const info = await PickCredential(role);
    if (info.loaded) setCred(role, true, info.fileName);
  } catch (e) {
    showImportError(e);
  }
}

// pickBundle imports a one-file .vpnio profile: the Go side opens the dialog,
// validates it and stages it. On success (hasProfile=true) we drop back to the
// main screen, now showing "Connect"; a cancel returns hasProfile=false.
async function pickBundle() {
  hideImportError();
  try {
    const info = await ImportProfileBundle();
    if (!info.hasProfile) return; // cancelled — draft unchanged
    showView('main');
    poll();
  } catch (e) {
    showImportError(e);
  }
}

async function openImport() {
  // Repopulate from the staged draft so reopening shows what's already set.
  try {
    const p = await Profile();
    impServer.value = p.server || '';
    impSni.value = p.serverName || '';
    impMtu.value = p.mtu ? String(p.mtu) : '';
    impTun.value = p.tunName || '';
    setCred('ca', p.ca.loaded, p.ca.fileName);
    setCred('cert', p.cert.loaded, p.cert.fileName);
    setCred('key', p.key.loaded, p.key.fileName);
  } catch (_) { /* fresh form on failure */ }
  actionError = '';
  hideImportError();
  showView('import');
  impServer.focus();
}

async function saveImport() {
  const form = {
    server: impServer.value.trim(),
    serverName: impSni.value.trim(),
    mtu: parseInt(impMtu.value, 10) || 0,
    tunName: impTun.value.trim(),
  };
  impSave.disabled = true;
  hideImportError();
  try {
    await Connect(form);
    showView('main');
    poll();
  } catch (e) {
    showImportError(e);
    updateSaveEnabled();
  }
}

function wireImport() {
  impBundle.onclick = pickBundle;
  credEls.ca.row.onclick = () => pick('ca');
  credEls.cert.row.onclick = () => pick('cert');
  credEls.key.row.onclick = () => pick('key');
  impServer.addEventListener('input', updateSaveEnabled);
  impSave.onclick = saveImport;
  impCancel.onclick = () => showView('main');
  impBack.onclick = () => showView('main');
  profileBtn.onclick = openImport;
}

// --- theme + boot --------------------------------------------------------

// Theme: a manual light/dark toggle, persisted. With no manual choice yet, we
// follow the OS preference (and keep following it as it changes); once the user
// flips the toggle, that choice sticks. A future "Auto" setting will clear the
// stored choice to return to following the OS.
const THEME_KEY = 'vpnio.theme';

function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  // Keep the toggle's accessible name pointing at what the next press does, so a
  // screen reader announces the direction (review #56).
  const toggle = el('theme-toggle');
  if (toggle) {
    toggle.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  }
}

function setupTheme() {
  const mq = matchMedia('(prefers-color-scheme: dark)');
  const saved = localStorage.getItem(THEME_KEY);
  setTheme(saved || (mq.matches ? 'dark' : 'light'));

  mq.addEventListener('change', () => {
    if (!localStorage.getItem(THEME_KEY)) setTheme(mq.matches ? 'dark' : 'light');
  });

  el('theme-toggle').onclick = () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem(THEME_KEY, next);
  };
}

// Tag the platform so CSS can drop the macOS-only traffic-light drag strip on
// Windows, whose native title bar already drags and closes the window.
if (navigator.userAgent.includes('Windows')) {
  document.documentElement.classList.add('os-windows');
}

setupTheme();
wireImport();
poll();
setInterval(poll, POLL_MS);
setInterval(updateTimer, 1000);
