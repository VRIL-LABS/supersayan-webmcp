/**
 * Glow — Background Service Worker
 * Message hub: stores scan results per tab, manages settings, updates badge,
 * fires alarms for periodic re-scans, and pushes notifications.
 */

import type { GlowMessage, GlowScanResult, GlowSettings } from './types';
import { DEFAULT_SETTINGS } from './types';

// ── In-memory result cache keyed by tabId ─────────────────────────────────────
const resultCache = new Map<number, GlowScanResult>();

// ── Badge color map ────────────────────────────────────────────────────────────
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

// ── Settings helpers ───────────────────────────────────────────────────────────
async function getSettings(): Promise<GlowSettings> {
  const stored = await chrome.storage.local.get('glowSettings');
  return (stored.glowSettings as GlowSettings) ?? DEFAULT_SETTINGS;
}

async function saveSettings(settings: GlowSettings): Promise<void> {
  await chrome.storage.local.set({ glowSettings: settings });
}

// ── Scan history helpers ───────────────────────────────────────────────────────
const MAX_HISTORY = 200;

async function appendHistory(result: GlowScanResult): Promise<void> {
  const settings = await getSettings();
  if (!settings.storeHistory) return;

  const stored = await chrome.storage.local.get('glowHistory');
  const history: GlowScanResult[] = (stored.glowHistory as GlowScanResult[]) ?? [];
  history.unshift(result);
  if (history.length > MAX_HISTORY) history.splice(MAX_HISTORY);
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
  await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[level] ?? '#00FFC8' });
  await chrome.action.setBadgeText({ tabId, text: BADGE_TEXT[level] ?? '' });
}

// ── Notification ──────────────────────────────────────────────────────────────
async function maybeNotify(result: GlowScanResult): Promise<void> {
  const settings = await getSettings();
  if (!settings.notifyHigh) return;
  if (result.threatLevel !== 'HIGH' && result.threatLevel !== 'CRITICAL') return;

  const hostname = (() => {
    try { return new URL(result.url).hostname; } catch { return result.url; }
  })();

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
    scans: number;
    threats: number;
    blocked: number;
    installedAt: number;
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
    // Content script not ready / frame mismatch — inject on demand
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ['content.js'],
      });
      // Brief pause for script init, then send
      await new Promise(r => setTimeout(r, 600));
      await chrome.tabs.sendMessage(tabId, { type: 'SCAN_REQUEST' } satisfies GlowMessage);
    } catch { /* tab closed or restricted URL */ }
  }
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener(
  (rawMessage: GlowMessage, sender, sendResponse) => {
    const message = rawMessage;

    if (message.type === 'SCAN_RESULT') {
      const result = message.result;
      const tabId = sender.tab?.id ?? result.tabId;
      result.tabId = tabId;
      resultCache.set(tabId, result);

      // Async side-effects — fire and forget from listener
      Promise.all([
        updateBadge(tabId, result),
        appendHistory(result),
        maybeNotify(result),
        incrementStats(result),
      ]).catch(() => {});

      sendResponse({ ok: true });
      return false;
    }

    if (message.type === 'GET_LAST_RESULT') {
      const tabId = message.tabId;
      const result = resultCache.get(tabId) ?? null;
      sendResponse({ type: 'LAST_RESULT_RESPONSE', result } satisfies GlowMessage);
      return false;
    }

    if (message.type === 'SCAN_REQUEST') {
      // Popup asking background to trigger a scan on the active tab
      chrome.tabs.query({ active: true, currentWindow: true }).then(tabs => {
        const tab = tabs[0];
        if (!tab?.id) { sendResponse({ ok: false }); return; }
        triggerScanOnTab(tab.id).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
      });
      return true;
    }

    if (message.type === 'GET_SETTINGS') {
      getSettings().then(settings => {
        sendResponse({ type: 'SETTINGS_RESPONSE', settings } satisfies GlowMessage);
      });
      return true;
    }

    if (message.type === 'UPDATE_SETTINGS') {
      getSettings().then(async current => {
        const merged: GlowSettings = {
          ...current,
          ...(message as { type: 'UPDATE_SETTINGS'; settings: Partial<GlowSettings> }).settings,
          guards: {
            ...current.guards,
            ...((message as { type: 'UPDATE_SETTINGS'; settings: Partial<GlowSettings> }).settings.guards ?? {}),
          },
        };
        await saveSettings(merged);
        // Push updated settings to all tabs' content scripts
        const tabs = await chrome.tabs.query({});
        tabs.forEach(tab => {
          if (tab.id) {
            chrome.tabs.sendMessage(tab.id, { type: 'UPDATE_SETTINGS', settings: merged } satisfies GlowMessage)
              .catch(() => {});
          }
        });
        sendResponse({ type: 'SETTINGS_UPDATED' } satisfies GlowMessage);
      });
      return true;
    }

    if (message.type === 'GET_HISTORY') {
      getHistory().then(history => {
        sendResponse({ type: 'HISTORY_RESPONSE', history } satisfies GlowMessage);
      });
      return true;
    }

    if (message.type === 'CLEAR_HISTORY') {
      chrome.storage.local.remove('glowHistory').then(() => {
        sendResponse({ ok: true });
      });
      return true;
    }

    return false;
  }
);

// ── Tab lifecycle ─────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(tabId => {
  resultCache.delete(tabId);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status !== 'complete') return;
  const settings = await getSettings();
  if (!settings.autoScan) return;

  // Short delay to let content script initialize
  setTimeout(() => triggerScanOnTab(tabId), 800);
});

// ── Alarm: periodic re-scan of active tab every 5 minutes ─────────────────────
chrome.alarms.create('glow-periodic-scan', { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name !== 'glow-periodic-scan') return;
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (tab?.id) triggerScanOnTab(tab.id);
});

// ── Install / update ──────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async details => {
  // Initialize default settings if first install
  const existing = await chrome.storage.local.get('glowSettings');
  if (!existing.glowSettings) {
    await saveSettings(DEFAULT_SETTINGS);
  }
  // Initialize stats
  const existingStats = await chrome.storage.local.get('glowStats');
  if (!existingStats.glowStats) {
    await chrome.storage.local.set({
      glowStats: { scans: 0, threats: 0, blocked: 0, installedAt: Date.now() },
    });
  }

  if (details.reason === 'install') {
    // Open options page on fresh install
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html') });
  }
});
