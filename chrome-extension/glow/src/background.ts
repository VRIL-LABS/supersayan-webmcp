/**
 * Glow — Background Service Worker
 *
 * All event listeners registered synchronously at top level (sw-register-listeners-toplevel).
 * Result cache uses chrome.storage.session — survives SW restarts, cleared on browser close
 * (sw-persist-state-storage). Alarm creation is idempotent (sw-use-alarms-api).
 * Async message handlers use a non-async wrapper to avoid the return-true trap
 * (sw-return-true-async, msg-check-lasterror). Settings broadcast removed — content scripts
 * now react to chrome.storage.onChanged instead of push messages.
 */

import type { GlowMessage, GlowScanResult, GlowSettings } from './types';
import { DEFAULT_SETTINGS } from './types';

// ── Constants ──────────────────────────────────────────────────────────────────
const ALARM_NAME = 'glow-periodic-scan';
const ALARM_PERIOD_MINUTES = 5;
const MAX_HISTORY = 200;
const SCAN_RESULT_CACHE_KEY = 'glowResultCache';

const BADGE_COLORS: Record<string, string> = {
  SAFE:     '#00FFC8',
  LOW:      '#00B4D8',
  MEDIUM:   '#FFC107',
  HIGH:     '#FF6B3D',
  CRITICAL: '#FF3B3B',
};

const BADGE_TEXT: Record<string, string> = {
  SAFE:     '',
  LOW:      'L',
  MEDIUM:   'M',
  HIGH:     'H',
  CRITICAL: '!!',
};

// ── Idempotent alarm creation ─────────────────────────────────────────────────
// Called at top level and in onInstalled — safe to call multiple times.
async function ensureAlarm(): Promise<void> {
  const existing = await chrome.alarms.get(ALARM_NAME);
  if (!existing) {
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: ALARM_PERIOD_MINUTES });
  }
}
ensureAlarm();

// ── session storage helpers for result cache ──────────────────────────────────
// chrome.storage.session persists across SW restarts but not browser close.
// This replaces the ephemeral in-memory Map that was lost on every SW termination.

async function getCachedResult(tabId: number): Promise<GlowScanResult | null> {
  const stored = await chrome.storage.session.get(SCAN_RESULT_CACHE_KEY);
  const cache = (stored[SCAN_RESULT_CACHE_KEY] as Record<string, GlowScanResult>) ?? {};
  return cache[String(tabId)] ?? null;
}

async function setCachedResult(tabId: number, result: GlowScanResult): Promise<void> {
  const stored = await chrome.storage.session.get(SCAN_RESULT_CACHE_KEY);
  const cache = (stored[SCAN_RESULT_CACHE_KEY] as Record<string, GlowScanResult>) ?? {};
  cache[String(tabId)] = result;
  await chrome.storage.session.set({ [SCAN_RESULT_CACHE_KEY]: cache });
}

async function deleteCachedResult(tabId: number): Promise<void> {
  const stored = await chrome.storage.session.get(SCAN_RESULT_CACHE_KEY);
  const cache = (stored[SCAN_RESULT_CACHE_KEY] as Record<string, GlowScanResult>) ?? {};
  delete cache[String(tabId)];
  await chrome.storage.session.set({ [SCAN_RESULT_CACHE_KEY]: cache });
}

// ── Settings helpers ───────────────────────────────────────────────────────────
async function getSettings(): Promise<GlowSettings> {
  const stored = await chrome.storage.local.get('glowSettings');
  return (stored.glowSettings as GlowSettings) ?? DEFAULT_SETTINGS;
}

async function saveSettings(settings: GlowSettings): Promise<void> {
  // Write to storage.local — content scripts listen via chrome.storage.onChanged
  // rather than receiving push messages, eliminating the broadcast-to-all-tabs antipattern.
  await chrome.storage.local.set({ glowSettings: settings });
}

// ── Scan history helpers ───────────────────────────────────────────────────────
async function appendHistory(result: GlowScanResult): Promise<void> {
  const settings = await getSettings();
  if (!settings.storeHistory) return;

  const stored = await chrome.storage.local.get('glowHistory');
  const history: GlowScanResult[] = (stored.glowHistory as GlowScanResult[]) ?? [];
  history.unshift(result);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  await chrome.storage.local.set({ glowHistory: history });
}

async function getHistory(): Promise<GlowScanResult[]> {
  const stored = await chrome.storage.local.get('glowHistory');
  return (stored.glowHistory as GlowScanResult[]) ?? [];
}

// ── Badge update ──────────────────────────────────────────────────────────────
async function updateBadge(tabId: number, result: GlowScanResult): Promise<void> {
  const settings = await getSettings();
  if (!settings.badge) {
    await chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  const level = result.threatLevel;
  await Promise.all([
    chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[level] ?? '#00FFC8' }),
    chrome.action.setBadgeText({ tabId, text: BADGE_TEXT[level] ?? '' }),
  ]);
}

// ── Notification ──────────────────────────────────────────────────────────────
async function maybeNotify(result: GlowScanResult): Promise<void> {
  const settings = await getSettings();
  if (!settings.notifyHigh) return;
  if (result.threatLevel !== 'HIGH' && result.threatLevel !== 'CRITICAL') return;

  let hostname = result.url;
  try { hostname = new URL(result.url).hostname; } catch { /* keep full url */ }

  chrome.notifications.create(`glow-${result.tabId}-${result.timestamp}`, {
    type: 'basic',
    iconUrl: 'icons/icon-48.png',
    title: `Glow: ${result.threatLevel} Threat Detected`,
    message: `${hostname} — Score ${result.overallScore}/100. ${result.recommendations[0] ?? ''}`,
    priority: result.threatLevel === 'CRITICAL' ? 2 : 1,
  });
}

// ── Stats counter ─────────────────────────────────────────────────────────────
async function incrementStats(result: GlowScanResult): Promise<void> {
  const stored = await chrome.storage.local.get('glowStats');
  const stats = (stored.glowStats as {
    scans: number; threats: number; blocked: number; installedAt: number;
  }) ?? { scans: 0, threats: 0, blocked: 0, installedAt: Date.now() };

  stats.scans += 1;
  if (result.threatLevel !== 'SAFE') stats.threats += 1;
  await chrome.storage.local.set({ glowStats: stats });
}

// ── Trigger a scan on a tab ───────────────────────────────────────────────────
async function triggerScanOnTab(tabId: number): Promise<void> {
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'SCAN_REQUEST' } satisfies GlowMessage);
  } catch {
    // Content script not ready — inject on demand then send
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
      // Use chrome.alarms for a brief delay instead of setTimeout (SW-safe)
      // For one-shot retry, just attempt immediately — the script init is synchronous
      await chrome.tabs.sendMessage(tabId, { type: 'SCAN_REQUEST' } satisfies GlowMessage);
    } catch {
      // Tab closed, restricted URL (chrome://, etc.) — silently ignore
    }
  }
}

// ── Async message handler wrapper ─────────────────────────────────────────────
// Returns literal `true` synchronously so Chrome keeps the channel open.
// Catches all async errors and sends them back as structured responses.
type MsgSender = chrome.runtime.MessageSender;

function asyncHandler<T>(
  fn: (msg: GlowMessage, sender: MsgSender) => Promise<T>,
): (msg: GlowMessage, sender: MsgSender, sendResponse: (r: unknown) => void) => true {
  return (msg, sender, sendResponse) => {
    fn(msg, sender)
      .then(sendResponse)
      .catch((err: unknown) => sendResponse({ __error: true, message: String(err) }));
    return true;
  };
}

// ── Message handler ───────────────────────────────────────────────────────────
// All listeners registered at top level synchronously.
chrome.runtime.onMessage.addListener((rawMsg: GlowMessage, sender, sendResponse) => {
  const msg = rawMsg;

  // ── SCAN_RESULT from content script ───────────────────────────────────────
  if (msg.type === 'SCAN_RESULT') {
    const result = msg.result;
    const tabId = sender.tab?.id ?? result.tabId;
    result.tabId = tabId;

    // Async side-effects — fire-and-forget, never block the listener
    Promise.all([
      setCachedResult(tabId, result),
      updateBadge(tabId, result),
      appendHistory(result),
      maybeNotify(result),
      incrementStats(result),
    ]).catch(() => {});

    sendResponse({ ok: true });
    return false; // synchronous response — no need to keep channel open
  }

  // ── All remaining handlers are async — use asyncHandler wrapper ────────────

  if (msg.type === 'GET_LAST_RESULT') {
    const tabId = (msg as { type: 'GET_LAST_RESULT'; tabId: number }).tabId;
    asyncHandler(async () => {
      const result = await getCachedResult(tabId);
      return { type: 'LAST_RESULT_RESPONSE', result } satisfies GlowMessage;
    })(msg, sender, sendResponse);
    return true;
  }

  if (msg.type === 'SCAN_REQUEST') {
    asyncHandler(async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab?.id) return { ok: false };
      await triggerScanOnTab(tab.id);
      return { ok: true };
    })(msg, sender, sendResponse);
    return true;
  }

  if (msg.type === 'GET_SETTINGS') {
    asyncHandler(async () => {
      const settings = await getSettings();
      return { type: 'SETTINGS_RESPONSE', settings } satisfies GlowMessage;
    })(msg, sender, sendResponse);
    return true;
  }

  if (msg.type === 'UPDATE_SETTINGS') {
    asyncHandler(async () => {
      const current = await getSettings();
      const patch = (msg as { type: 'UPDATE_SETTINGS'; settings: Partial<GlowSettings> }).settings;
      const merged: GlowSettings = {
        ...current,
        ...patch,
        guards: { ...current.guards, ...(patch.guards ?? {}) },
      };
      await saveSettings(merged);
      // Content scripts pick up the change via chrome.storage.onChanged — no broadcast needed.
      return { type: 'SETTINGS_UPDATED' } satisfies GlowMessage;
    })(msg, sender, sendResponse);
    return true;
  }

  if (msg.type === 'GET_HISTORY') {
    asyncHandler(async () => {
      const history = await getHistory();
      return { type: 'HISTORY_RESPONSE', history } satisfies GlowMessage;
    })(msg, sender, sendResponse);
    return true;
  }

  if (msg.type === 'CLEAR_HISTORY') {
    asyncHandler(async () => {
      await chrome.storage.local.remove('glowHistory');
      return { ok: true };
    })(msg, sender, sendResponse);
    return true;
  }

  return false;
});

// ── Tab lifecycle ─────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  deleteCachedResult(tabId).catch(() => {});
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status !== 'complete') return;
  const settings = await getSettings();
  if (!settings.autoScan) return;
  // Use a one-shot alarm for the post-load delay instead of setTimeout
  // (SW-safe; setTimeout is cancelled on SW termination).
  // Smallest possible delay at 0.5 min (30s) — minimum alarm period in Chrome 120+.
  // For practical UX we send immediately; the content script bootstraps on document_idle
  // so it is ready by the time tabs.onUpdated fires with status:'complete'.
  triggerScanOnTab(tabId).catch(() => {});
});

// ── Alarm: periodic re-scan ────────────────────────────────────────────────────
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== ALARM_NAME) return;
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (tab?.id) triggerScanOnTab(tab.id).catch(() => {});
});

// ── Install / update ──────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  // Initialize defaults on first install
  const existing = await chrome.storage.local.get('glowSettings');
  if (!existing.glowSettings) {
    await saveSettings(DEFAULT_SETTINGS);
  }
  const existingStats = await chrome.storage.local.get('glowStats');
  if (!existingStats.glowStats) {
    await chrome.storage.local.set({
      glowStats: { scans: 0, threats: 0, blocked: 0, installedAt: Date.now() },
    });
  }
  // Ensure alarm exists after install/update
  await ensureAlarm();

  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html') });
  }
});

// ── Startup: re-ensure alarm after browser restart ─────────────────────────────
chrome.runtime.onStartup.addListener(() => {
  ensureAlarm().catch(() => {});
});
