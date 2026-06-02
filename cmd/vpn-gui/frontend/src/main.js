import './style.css';
import { Status, Disconnect } from '../wailsjs/go/main/App';

// The window mirrors the daemon: every ~1.5s we poll Status() and re-render the
// whole tray from the result, so the UI never asserts a state the daemon isn't
// actually in. Disconnect/Cancel drive the daemon directly. Connecting needs
// credentials, which the import screen (the next step) supplies — until then
// the primary "Connect"/"Try again" action is disabled.

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
const stateLabel = el('state-label');
const stateSub = el('state-sub');
const profileName = el('profile-name');
const timer = el('timer');
const notice = el('notice');
const noticeDetail = el('notice-detail');
const actionBtn = el('action-btn');

// sinceUnix drives the session timer; 0 means "not connected" (timer hidden).
let sinceUnix = 0;

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// hostOf drops the :port for the profile-chip label (the full host:port stays
// on the state sub-line).
function hostOf(server) {
  return String(server).replace(/:\d+$/, '');
}

function updateTimer() {
  if (!sinceUnix) return;
  const s = Math.max(0, Math.floor(Date.now() / 1000) - sinceUnix);
  const pad = (n) => String(n).padStart(2, '0');
  timer.textContent = `${pad(Math.floor(s / 3600))}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
}

async function doDisconnect() {
  actionBtn.disabled = true;
  try {
    await Disconnect();
  } catch (e) {
    console.error('disconnect failed:', e);
  }
  poll(); // reflect the new state immediately rather than waiting for the tick
}

// applyAction sets the primary button's label, style and handler for the state.
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
      // Retrying needs the credentials the import screen will hold.
      actionBtn.classList.add('btn--primary');
      actionBtn.textContent = 'Try again';
      actionBtn.disabled = true;
      break;
    default: // disconnected (and the helper-offline pseudo-state)
      actionBtn.classList.add('btn--primary');
      actionBtn.textContent = 'Connect';
      actionBtn.disabled = true;
  }
}

// render paints the whole tray from a status snapshot. reachable=false means
// the Status call itself failed (typically the background helper isn't
// running); we show that as a disconnected window with a clear hint.
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
    subHTML = 'Import a profile to connect';
  }
  stateSub.innerHTML = subHTML;
  stateSub.classList.toggle('is-hidden', subHTML === '');

  profileName.textContent = reachable && st.server ? hostOf(st.server) : 'vpn.io';

  if (reachable && state === 'connected' && st.sinceUnix > 0) {
    sinceUnix = st.sinceUnix;
    timer.classList.remove('is-hidden');
    updateTimer();
  } else {
    sinceUnix = 0;
    timer.classList.add('is-hidden');
  }

  if (reachable && state === 'failed') {
    noticeDetail.textContent = st.lastError || 'The connection could not be established.';
    notice.classList.remove('is-hidden');
  } else {
    notice.classList.add('is-hidden');
  }

  applyAction(state);
}

let polling = false;
async function poll() {
  if (polling) return; // don't overlap if a slow call is still in flight
  polling = true;
  try {
    const st = await Status();
    render(st, true);
  } catch (e) {
    render({ state: 'disconnected' }, false);
  } finally {
    polling = false;
  }
}

function setupTheme() {
  const mq = matchMedia('(prefers-color-scheme: dark)');
  const apply = () =>
    document.documentElement.setAttribute('data-theme', mq.matches ? 'dark' : 'light');
  apply();
  mq.addEventListener('change', apply);
}

setupTheme();
poll();
setInterval(poll, POLL_MS);
setInterval(updateTimer, 1000);
