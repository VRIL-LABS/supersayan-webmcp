/**
 * Glow — Popup Script
 *
 * Render the threat dashboard using cached result from background on open.
 * Scan flow: popup → background (SCAN_REQUEST) → content (SCAN_REQUEST) →
 *   background (SCAN_RESULT stored) → popup polls GET_LAST_RESULT.
 * The background service worker cannot push to the popup via sendMessage
 * (popup is not a tab), so we poll after triggering a scan.
 * Orphan detection on every chrome.runtime call (api-handle-context-invalidated).
 */

import type { GlowMessage, GlowScanResult, GlowShieldStatus } from './types';

// ── Orphan guard ──────────────────────────────────────────────────────────────
function isAlive(): boolean {
  try { return !!chrome.runtime?.id; } catch { return false; }
}

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $threatBanner    = document.getElementById('threatBanner')!;
const $threatIndicator = document.getElementById('threatIndicator')!;
const $threatLabel     = document.getElementById('threatLabel')!;
const $threatDesc      = document.getElementById('threatDesc')!;
const $threatScore     = document.getElementById('threatScore')!;
const $scanBtn         = document.getElementById('scanBtn') as HTMLButtonElement;
const $scanBtnText     = document.getElementById('scanBtnText')!;
const $signalsList     = document.getElementById('signalsList')!;
const $signalsTitle    = document.getElementById('signalsTitle')!;
const $scanTime        = document.getElementById('scanTime')!;
const $urlBar          = document.getElementById('urlBar')!;
const $settingsBtn     = document.getElementById('settingsBtn')!;
const $refreshBtn      = document.getElementById('refreshBtn')!;
const $exportBtn       = document.getElementById('exportBtn')!;
const $optionsLink     = document.getElementById('optionsLink')!;

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

// ── State ─────────────────────────────────────────────────────────────────────
let lastResult: GlowScanResult | null = null;

// ── Render ────────────────────────────────────────────────────────────────────
function renderThreat(result: GlowScanResult): void {
  lastResult = result;
  const cls = THREAT_CLASS[result.threatLevel] ?? 'safe';

  $threatBanner.className = `threat-banner ${cls}`;
  $threatIndicator.innerHTML = THREAT_ICON[result.threatLevel] ?? '?';
  $threatLabel.textContent = result.threatLevel;
  $threatDesc.textContent = THREAT_DESC_TEXT[result.threatLevel] ?? '';
  $threatScore.innerHTML = `${result.overallScore}<span>/100</span>`;

  const d = new Date(result.timestamp);
  $scanTime.textContent = `Last scan: ${d.toLocaleTimeString()}`;

  try {
    const u = new URL(result.url);
    $urlBar.innerHTML = `<span>${escHtml(u.hostname)}</span>${u.pathname.length > 1 ? escHtml(u.pathname.slice(0, 32)) : ''}`;
  } catch {
    $urlBar.textContent = result.url.slice(0, 48);
  }

  renderShieldGrid(result.shieldStatus);
  renderSignals(result);
}

function renderShieldGrid(status: GlowShieldStatus): void {
  const MAP: Record<keyof GlowShieldStatus, string> = {
    msti:           'msti',
    aiAgent:        'ai-agent',
    webrtc:         'webrtc',
    toolIntegrity:  'tool-integrity',
    session:        'session',
    gpu:            'gpu',
    elicitation:    'elicitation',
    supplyChain:    'supply-chain',
    quicReplay:     'quic-replay',
    cssKey:         'css-key',
    abortExecution: 'abort',
    declForm:       'decl-form',
  };
  for (const key of Object.keys(MAP) as Array<keyof GlowShieldStatus>) {
    const el = document.querySelector<HTMLElement>(`[data-guard="${MAP[key]}"]`);
    if (!el) continue;
    const s = status[key];
    el.className = `shield-item ${s === 'active' ? 'active' : s === 'alert' ? 'alert' : 'inactive'}`;
  }
}

function renderSignals(result: GlowScanResult): void {
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
        <span class="signal-icon" aria-hidden="true">${icon}</span>
        <span class="signal-name">${escHtml(sig.name)}</span>
        <span class="signal-badge ${badgeCls}" aria-label="${badgeText}">${badgeText}</span>
      </div>`;
  }).join('');
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showScanning(scanning: boolean): void {
  $scanBtn.disabled = scanning;
  $scanBtn.classList.toggle('scanning', scanning);
  $scanBtnText.innerHTML = scanning ? '&#9654; Scanning...' : '&#9656; Run Full Scan';
}

// ── Active tab helpers ────────────────────────────────────────────────────────
async function getActiveTab(): Promise<chrome.tabs.Tab | null> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] ?? null;
}

// ── Load existing cached result from background ───────────────────────────────
async function loadResult(): Promise<void> {
  if (!isAlive()) return;

  const tab = await getActiveTab();
  if (!tab?.id) return;

  // Show URL optimistically from tab info
  if (tab.url) {
    try {
      const u = new URL(tab.url);
      $urlBar.innerHTML = `<span>${escHtml(u.hostname)}</span>${u.pathname.length > 1 ? escHtml(u.pathname.slice(0, 32)) : ''}`;
    } catch {
      $urlBar.textContent = tab.url.slice(0, 48);
    }
  }

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'GET_LAST_RESULT',
      tabId: tab.id,
    } satisfies GlowMessage) as GlowMessage;

    if (resp.type === 'LAST_RESULT_RESPONSE' && resp.result) {
      renderThreat(resp.result);
    }
  } catch { /* background may not have a result yet for this tab */ }
}

// ── Trigger scan and poll for result ─────────────────────────────────────────
// Flow: popup → background (SCAN_REQUEST) → content script (SCAN_REQUEST) →
//       background receives SCAN_RESULT → popup polls GET_LAST_RESULT.
// Background cannot push to popup (popup is not a tab context).
async function triggerScan(): Promise<void> {
  if (!isAlive()) return;
  showScanning(true);

  const tab = await getActiveTab();
  if (!tab?.id) {
    showScanning(false);
    return;
  }

  try {
    await chrome.runtime.sendMessage({ type: 'SCAN_REQUEST' } satisfies GlowMessage);
  } catch {
    showScanning(false);
    return;
  }

  // Poll for the result — retry up to 8 times with 500ms intervals (4s total)
  let attempts = 0;
  const poll = (): void => {
    attempts++;
    if (!isAlive()) { showScanning(false); return; }

    chrome.runtime.sendMessage({
      type: 'GET_LAST_RESULT',
      tabId: tab.id!,
    } satisfies GlowMessage)
      .then((resp: GlowMessage) => {
        if (resp.type === 'LAST_RESULT_RESPONSE' && resp.result) {
          showScanning(false);
          renderThreat(resp.result);
        } else if (attempts < 8) {
          setTimeout(poll, 500);
        } else {
          showScanning(false);
        }
      })
      .catch(() => { showScanning(false); });
  };
  setTimeout(poll, 600);
}

// ── Export ────────────────────────────────────────────────────────────────────
$exportBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `glow-scan-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

// ── Event listeners ───────────────────────────────────────────────────────────
$scanBtn.addEventListener('click', triggerScan);
$refreshBtn.addEventListener('click', triggerScan);
$settingsBtn.addEventListener('click', () => {
  if (isAlive()) chrome.runtime.openOptionsPage();
});
$optionsLink.addEventListener('click', () => {
  if (isAlive()) chrome.runtime.openOptionsPage();
});

// ── Init ──────────────────────────────────────────────────────────────────────
loadResult();
