/**
 * Glow — Options Page Script
 *
 * Reads settings via chrome.runtime.sendMessage (routed through background) so
 * all contexts share a single source of truth. chrome.storage.local.get used
 * directly only for stats (read-only, no mutation path). Orphan detection on
 * every chrome.runtime call (api-handle-context-invalidated). Auto-save on every
 * toggle change (options-auto-save).
 */

import type { GlowMessage, GlowScanResult, GlowSettings } from './types';
import { DEFAULT_SETTINGS } from './types';

// ── Orphan guard ──────────────────────────────────────────────────────────────
function isAlive(): boolean {
  try { return !!chrome.runtime?.id; } catch { return false; }
}

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $scanLog      = document.getElementById('scanLog')!;
const $exportBtn    = document.getElementById('exportBtn')!;
const $exportCsvBtn = document.getElementById('exportCsvBtn')!;
const $clearHistory = document.getElementById('clearHistoryBtn')!;
const $statScans    = document.getElementById('statScans')!;
const $statThreats  = document.getElementById('statThreats')!;
const $statBlocked  = document.getElementById('statBlocked')!;
const $statDays     = document.getElementById('statDays')!;

// ── Guard / setting toggle maps ───────────────────────────────────────────────
const GUARD_IDS: Array<{ id: string; key: keyof GlowSettings['guards'] }> = [
  { id: 'guard-msti',           key: 'msti' },
  { id: 'guard-ai-agent',       key: 'aiAgent' },
  { id: 'guard-webrtc',         key: 'webrtc' },
  { id: 'guard-tool-integrity', key: 'toolIntegrity' },
  { id: 'guard-session',        key: 'session' },
  { id: 'guard-gpu',            key: 'gpu' },
  { id: 'guard-elicitation',    key: 'elicitation' },
  { id: 'guard-abort',          key: 'abortExecution' },
  { id: 'guard-decl-form',      key: 'declForm' },
  { id: 'guard-supply-chain',   key: 'supplyChain' },
  { id: 'guard-quic-replay',    key: 'quicReplay' },
  { id: 'guard-css-key',        key: 'cssKey' },
];

const SETTING_IDS: Array<{ id: string; key: keyof Omit<GlowSettings, 'guards'> }> = [
  { id: 'setting-auto-scan',   key: 'autoScan' },
  { id: 'setting-badge',       key: 'badge' },
  { id: 'setting-notify-high', key: 'notifyHigh' },
  { id: 'setting-history',     key: 'storeHistory' },
];

let currentSettings: GlowSettings = DEFAULT_SETTINGS;
let currentHistory: GlowScanResult[] = [];

// ── Load settings ──────────────────────────────────────────────────────────────
async function loadSettings(): Promise<void> {
  if (!isAlive()) return;
  try {
    const resp = await chrome.runtime.sendMessage(
      { type: 'GET_SETTINGS' } satisfies GlowMessage,
    ) as GlowMessage;
    if (resp.type === 'SETTINGS_RESPONSE') {
      currentSettings = resp.settings;
    }
  } catch { /* background unavailable — use defaults */ }
  applySettingsToUI(currentSettings);
}

function applySettingsToUI(settings: GlowSettings): void {
  for (const { id, key } of GUARD_IDS) {
    const el = document.getElementById(id) as HTMLInputElement | null;
    if (el) el.checked = settings.guards[key];
  }
  for (const { id, key } of SETTING_IDS) {
    const el = document.getElementById(id) as HTMLInputElement | null;
    if (el) el.checked = settings[key] as boolean;
  }
}

// ── Auto-save on toggle change ─────────────────────────────────────────────────
function attachToggleListeners(): void {
  for (const { id, key } of GUARD_IDS) {
    const el = document.getElementById(id) as HTMLInputElement | null;
    el?.addEventListener('change', () => {
      currentSettings = {
        ...currentSettings,
        guards: { ...currentSettings.guards, [key]: el.checked },
      };
      persistSettings();
    });
  }
  for (const { id, key } of SETTING_IDS) {
    const el = document.getElementById(id) as HTMLInputElement | null;
    el?.addEventListener('change', () => {
      currentSettings = { ...currentSettings, [key]: el.checked };
      persistSettings();
    });
  }
}

async function persistSettings(): Promise<void> {
  if (!isAlive()) return;
  try {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: currentSettings,
    } satisfies GlowMessage);
  } catch { /* background not ready */ }
}

// ── Load history ──────────────────────────────────────────────────────────────
async function loadHistory(): Promise<void> {
  if (!isAlive()) return;
  try {
    const resp = await chrome.runtime.sendMessage(
      { type: 'GET_HISTORY' } satisfies GlowMessage,
    ) as GlowMessage;
    if (resp.type === 'HISTORY_RESPONSE') {
      currentHistory = resp.history;
    }
  } catch { /* no history */ }
  renderHistory(currentHistory);
}

function renderHistory(history: GlowScanResult[]): void {
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
        <span class="log-threat ${cls}" aria-label="Threat: ${r.threatLevel}">${r.threatLevel}</span>
      </div>`;
  }).join('');
}

// ── Load stats ─────────────────────────────────────────────────────────────────
async function loadStats(): Promise<void> {
  try {
    const stored = await chrome.storage.local.get('glowStats');
    const stats = stored.glowStats as {
      scans: number; threats: number; blocked: number; installedAt: number;
    } | undefined;
    if (!stats) return;
    $statScans.textContent   = String(stats.scans);
    $statThreats.textContent = String(stats.threats);
    $statBlocked.textContent = String(stats.blocked);
    const days = Math.floor((Date.now() - (stats.installedAt ?? Date.now())) / 86_400_000);
    $statDays.textContent = String(days);
  } catch { /* storage unavailable */ }
}

// ── Export helpers ────────────────────────────────────────────────────────────
function downloadBlob(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

$exportBtn.addEventListener('click', () => {
  downloadBlob(
    JSON.stringify(currentHistory, null, 2),
    `glow-history-${Date.now()}.json`,
    'application/json',
  );
});

$exportCsvBtn.addEventListener('click', () => {
  const header = 'timestamp,url,threatLevel,overallScore\n';
  const rows = currentHistory
    .map(r => `${r.timestamp},"${r.url.replace(/"/g, '""')}",${r.threatLevel},${r.overallScore}`)
    .join('\n');
  downloadBlob(header + rows, `glow-history-${Date.now()}.csv`, 'text/csv');
});

$clearHistory.addEventListener('click', async () => {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  if (!isAlive()) return;
  try {
    await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' } satisfies GlowMessage);
    currentHistory = [];
    renderHistory([]);
    $statScans.textContent   = '0';
    $statThreats.textContent = '0';
  } catch { /* background not ready */ }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
(async () => {
  attachToggleListeners();
  await Promise.all([loadSettings(), loadHistory(), loadStats()]);
})();
