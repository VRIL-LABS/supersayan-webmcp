/**
 * Glow — Options Page Script
 * Renders settings toggles (guards + scan behavior), displays scan history,
 * and provides JSON/CSV export and history clearing.
 */

import type { GlowMessage, GlowScanResult, GlowSettings } from './types';
import { DEFAULT_SETTINGS } from './types';

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $scanLog       = document.getElementById('scanLog')!;
const $exportBtn     = document.getElementById('exportBtn')!;
const $exportCsvBtn  = document.getElementById('exportCsvBtn')!;
const $clearHistory  = document.getElementById('clearHistoryBtn')!;
const $statScans     = document.getElementById('statScans')!;
const $statThreats   = document.getElementById('statThreats')!;
const $statBlocked   = document.getElementById('statBlocked')!;
const $statDays      = document.getElementById('statDays')!;

// ── Guard toggle IDs ──────────────────────────────────────────────────────────
const GUARD_IDS: Array<{ id: string; key: keyof GlowSettings['guards'] }> = [
  { id: 'guard-msti',         key: 'msti' },
  { id: 'guard-ai-agent',     key: 'aiAgent' },
  { id: 'guard-webrtc',       key: 'webrtc' },
  { id: 'guard-tool-integrity', key: 'toolIntegrity' },
  { id: 'guard-session',      key: 'session' },
  { id: 'guard-gpu',          key: 'gpu' },
  { id: 'guard-elicitation',  key: 'elicitation' },
  { id: 'guard-abort',        key: 'abortExecution' },
  { id: 'guard-decl-form',    key: 'declForm' },
  { id: 'guard-supply-chain', key: 'supplyChain' },
  { id: 'guard-quic-replay',  key: 'quicReplay' },
  { id: 'guard-css-key',      key: 'cssKey' },
];

const SETTING_IDS: Array<{ id: string; key: keyof Omit<GlowSettings, 'guards'> }> = [
  { id: 'setting-auto-scan',    key: 'autoScan' },
  { id: 'setting-badge',        key: 'badge' },
  { id: 'setting-notify-high',  key: 'notifyHigh' },
  { id: 'setting-history',      key: 'storeHistory' },
];

let currentSettings: GlowSettings = DEFAULT_SETTINGS;
let currentHistory: GlowScanResult[] = [];

// ── Load settings from background ────────────────────────────────────────────
async function loadSettings() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' } satisfies GlowMessage) as GlowMessage;
    if (resp.type === 'SETTINGS_RESPONSE') {
      currentSettings = resp.settings;
    }
  } catch { /* use defaults */ }
  applySettingsToUI(currentSettings);
}

function applySettingsToUI(settings: GlowSettings) {
  GUARD_IDS.forEach(({ id, key }) => {
    const el = document.getElementById(id) as HTMLInputElement | null;
    if (el) el.checked = settings.guards[key];
  });
  SETTING_IDS.forEach(({ id, key }) => {
    const el = document.getElementById(id) as HTMLInputElement | null;
    if (el) el.checked = settings[key] as boolean;
  });
}

// ── Save on any toggle change ─────────────────────────────────────────────────
function attachToggleListeners() {
  GUARD_IDS.forEach(({ id, key }) => {
    const el = document.getElementById(id) as HTMLInputElement | null;
    el?.addEventListener('change', () => {
      currentSettings = {
        ...currentSettings,
        guards: { ...currentSettings.guards, [key]: el.checked },
      };
      persistSettings();
    });
  });
  SETTING_IDS.forEach(({ id, key }) => {
    const el = document.getElementById(id) as HTMLInputElement | null;
    el?.addEventListener('change', () => {
      currentSettings = { ...currentSettings, [key]: el.checked };
      persistSettings();
    });
  });
}

async function persistSettings() {
  try {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: currentSettings,
    } satisfies GlowMessage);
  } catch { /* background not ready */ }
}

// ── Load history ──────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_HISTORY' } satisfies GlowMessage) as GlowMessage;
    if (resp.type === 'HISTORY_RESPONSE') {
      currentHistory = resp.history;
    }
  } catch { /* no history */ }
  renderHistory(currentHistory);
}

function renderHistory(history: GlowScanResult[]) {
  if (history.length === 0) {
    $scanLog.innerHTML = '<div class="empty-log">No scans recorded yet. Visit a page and run a scan.</div>';
    return;
  }

  const THREAT_CLASS: Record<string, string> = {
    SAFE: 'safe', LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical',
  };

  $scanLog.innerHTML = history.slice(0, 80).map(r => {
    const time = new Date(r.timestamp).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
    let hostname = r.url;
    try { hostname = new URL(r.url).hostname; } catch { /* keep full url */ }
    const cls = THREAT_CLASS[r.threatLevel] ?? 'safe';
    return `
      <div class="log-entry">
        <span class="log-time">${time}</span>
        <span class="log-url" title="${escHtml(r.url)}">${escHtml(hostname)}</span>
        <span class="log-threat ${cls}">${r.threatLevel}</span>
      </div>`;
  }).join('');
}

// ── Load stats ─────────────────────────────────────────────────────────────────
async function loadStats() {
  const stored = await chrome.storage.local.get('glowStats');
  const stats = stored.glowStats as { scans: number; threats: number; blocked: number; installedAt: number } | undefined;
  if (!stats) return;
  $statScans.textContent = String(stats.scans);
  $statThreats.textContent = String(stats.threats);
  $statBlocked.textContent = String(stats.blocked);
  const days = Math.floor((Date.now() - (stats.installedAt ?? Date.now())) / 86_400_000);
  $statDays.textContent = String(days);
}

// ── Export helpers ────────────────────────────────────────────────────────────
function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

$exportBtn.addEventListener('click', () => {
  downloadBlob(
    JSON.stringify(currentHistory, null, 2),
    `glow-history-${Date.now()}.json`,
    'application/json'
  );
});

$exportCsvBtn.addEventListener('click', () => {
  const header = 'timestamp,url,threatLevel,overallScore\n';
  const rows = currentHistory.map(r =>
    `${r.timestamp},"${r.url.replace(/"/g, '""')}",${r.threatLevel},${r.overallScore}`
  ).join('\n');
  downloadBlob(header + rows, `glow-history-${Date.now()}.csv`, 'text/csv');
});

$clearHistory.addEventListener('click', async () => {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  try {
    await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' } satisfies GlowMessage);
    currentHistory = [];
    renderHistory([]);
    $statScans.textContent = '0';
    $statThreats.textContent = '0';
  } catch { /* bg not ready */ }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
(async () => {
  attachToggleListeners();
  await Promise.all([loadSettings(), loadHistory(), loadStats()]);
})();
