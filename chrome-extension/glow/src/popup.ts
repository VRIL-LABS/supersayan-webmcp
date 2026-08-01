/**
 * Glow — Popup Script
 * Queries the background for the latest scan result on the active tab,
 * renders the threat dashboard, shield grid and signals list, and triggers
 * on-demand scans.
 */

import type { GlowMessage, GlowScanResult, GlowShieldStatus } from './types';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $threatBanner   = document.getElementById('threatBanner')!;
const $threatIndicator = document.getElementById('threatIndicator')!;
const $threatLabel    = document.getElementById('threatLabel')!;
const $threatDesc     = document.getElementById('threatDesc')!;
const $threatScore    = document.getElementById('threatScore')!;
const $scanBtn        = document.getElementById('scanBtn')!;
const $scanBtnText    = document.getElementById('scanBtnText')!;
const $signalsList    = document.getElementById('signalsList')!;
const $signalsTitle   = document.getElementById('signalsTitle')!;
const $scanTime       = document.getElementById('scanTime')!;
const $urlBar         = document.getElementById('urlBar')!;
const $settingsBtn    = document.getElementById('settingsBtn')!;
const $refreshBtn     = document.getElementById('refreshBtn')!;
const $exportBtn      = document.getElementById('exportBtn')!;
const $optionsLink    = document.getElementById('optionsLink')!;

// ── Threat level config ───────────────────────────────────────────────────────
const THREAT_CLASS: Record<string, string> = {
  SAFE: 'safe', LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical',
};
const THREAT_ICON: Record<string, string> = {
  SAFE: '&#10003;', LOW: '&#9651;', MEDIUM: '&#9888;', HIGH: '&#10006;', CRITICAL: '&#9888;',
};
const THREAT_DESC_TEXT: Record<string, string> = {
  SAFE:     'No significant threats detected',
  LOW:      'Minor anomalies detected — monitor',
  MEDIUM:   'Suspicious signals present on this page',
  HIGH:     'Active threats detected — take action',
  CRITICAL: 'Critical WebMCP threat — immediate risk',
};

// ── Render functions ──────────────────────────────────────────────────────────
let lastResult: GlowScanResult | null = null;

function renderThreat(result: GlowScanResult) {
  lastResult = result;
  const cls = THREAT_CLASS[result.threatLevel] ?? 'safe';

  // Banner
  $threatBanner.className = `threat-banner ${cls}`;
  $threatIndicator.innerHTML = THREAT_ICON[result.threatLevel] ?? '?';
  $threatLabel.textContent = result.threatLevel;
  $threatDesc.textContent = THREAT_DESC_TEXT[result.threatLevel] ?? '';
  $threatScore.innerHTML = `${result.overallScore}<span>/100</span>`;

  // Timestamp
  const d = new Date(result.timestamp);
  $scanTime.textContent = `Last scan: ${d.toLocaleTimeString()}`;

  // URL bar
  try {
    const u = new URL(result.url);
    $urlBar.innerHTML = `<span>${u.hostname}</span>${u.pathname.length > 1 ? u.pathname.slice(0, 32) : ''}`;
  } catch {
    $urlBar.textContent = result.url.slice(0, 48);
  }

  // Shield grid
  renderShieldGrid(result.shieldStatus);

  // Signals
  renderSignals(result);
}

function renderShieldGrid(status: GlowShieldStatus) {
  const MAP: Record<keyof GlowShieldStatus, string> = {
    msti:          'msti',
    aiAgent:       'ai-agent',
    webrtc:        'webrtc',
    toolIntegrity: 'tool-integrity',
    session:       'session',
    gpu:           'gpu',
    elicitation:   'elicitation',
    supplyChain:   'supply-chain',
    quicReplay:    'quic-replay',
    cssKey:        'css-key',
    abortExecution:'abort',
    declForm:      'decl-form',
  };
  (Object.keys(MAP) as Array<keyof GlowShieldStatus>).forEach(key => {
    const el = document.querySelector<HTMLElement>(`[data-guard="${MAP[key]}"]`);
    if (!el) return;
    const s = status[key];
    el.className = `shield-item ${s === 'active' ? 'active' : s === 'alert' ? 'alert' : 'inactive'}`;
  });
}

function renderSignals(result: GlowScanResult) {
  const flagged = result.signals.filter(s => !s.passed);

  if (flagged.length === 0) {
    $signalsTitle.style.display = 'none';
    $signalsList.innerHTML = '';
    return;
  }

  $signalsTitle.style.display = '';
  const CATEGORY_ICON: Record<string, string> = {
    headless:       '&#128100;',
    automation:     '&#9881;',
    ai_agent:       '&#129302;',
    webmcp:         '&#9760;',
    covert_channel: '&#128065;',
  };

  $signalsList.innerHTML = flagged.slice(0, 8).map(sig => {
    const icon = CATEGORY_ICON[sig.category] ?? '&#9679;';
    const badgeCls = sig.passed ? 'pass' : sig.weight < 10 ? 'warn' : 'fail';
    const badgeText = sig.passed ? 'OK' : sig.weight >= 20 ? 'CRIT' : 'FAIL';
    return `
      <div class="signal-row" title="${escHtml(sig.details)}">
        <span class="signal-icon">${icon}</span>
        <span class="signal-name">${escHtml(sig.name)}</span>
        <span class="signal-badge ${badgeCls}">${badgeText}</span>
      </div>`;
  }).join('');
}

function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showScanning(scanning: boolean) {
  ($scanBtn as HTMLButtonElement).disabled = scanning;
  $scanBtn.classList.toggle('scanning', scanning);
  $scanBtnText.innerHTML = scanning ? '&#9654; Scanning...' : '&#9656; Run Full Scan';
}

// ── Active tab helpers ────────────────────────────────────────────────────────
async function getActiveTabId(): Promise<number | null> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.id ?? null;
}

// ── Load existing result ──────────────────────────────────────────────────────
async function loadResult() {
  const tabId = await getActiveTabId();
  if (!tabId) return;

  // Show URL optimistically
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (tab?.url) {
    try {
      const u = new URL(tab.url);
      $urlBar.innerHTML = `<span>${u.hostname}</span>${u.pathname.length > 1 ? u.pathname.slice(0, 32) : ''}`;
    } catch {
      $urlBar.textContent = tab.url.slice(0, 48);
    }
  }

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'GET_LAST_RESULT',
      tabId,
    } satisfies GlowMessage) as GlowMessage;

    if (resp.type === 'LAST_RESULT_RESPONSE' && resp.result) {
      renderThreat(resp.result);
    }
  } catch { /* background may not have result yet */ }
}

// ── Trigger scan ──────────────────────────────────────────────────────────────
async function triggerScan() {
  showScanning(true);
  try {
    await chrome.runtime.sendMessage({ type: 'SCAN_REQUEST' } satisfies GlowMessage);
    // Wait for SCAN_RESULT to come back via onMessage
  } catch {
    showScanning(false);
  }
}

// ── Listen for scan results pushed from background ────────────────────────────
chrome.runtime.onMessage.addListener((msg: GlowMessage) => {
  if (msg.type === 'SCAN_RESULT') {
    showScanning(false);
    renderThreat(msg.result);
  }
});

// ── Export ────────────────────────────────────────────────────────────────────
$exportBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `glow-scan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// ── Event listeners ───────────────────────────────────────────────────────────
$scanBtn.addEventListener('click', triggerScan);
$refreshBtn.addEventListener('click', triggerScan);
$settingsBtn.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
$optionsLink.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

// ── Init ──────────────────────────────────────────────────────────────────────
loadResult();
