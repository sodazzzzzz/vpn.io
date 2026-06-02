import './style.css';
import { Status, Disconnect, PickCredential, Connect, Reconnect, Profile } from '../wailsjs/go/main/App';
import { WindowSetSize } from '../wailsjs/runtime/runtime';

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

// Size the native window to the visible view's content (the hidden view is
// display:none, so it contributes no height). No-op outside Wails (e.g. a
// headless render), where the runtime isn't injected.
function resizeToContent() {
  requestAnimationFrame(() => {
    const h = Math.ceil(tray.getBoundingClientRect().height);
    if (h > 0) {
      try { WindowSetSize(360, h); } catch (_) { /* not running under Wails */ }
    }
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

function setupTheme() {
  const mq = matchMedia('(prefers-color-scheme: dark)');
  const apply = () =>
    document.documentElement.setAttribute('data-theme', mq.matches ? 'dark' : 'light');
  apply();
  mq.addEventListener('change', apply);
}

setupTheme();
wireImport();
poll();
setInterval(poll, POLL_MS);
setInterval(updateTimer, 1000);
