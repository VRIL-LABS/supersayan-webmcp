/**
 * Glow — Content Script (document_idle)
 *
 * Orphan detection on every chrome.runtime call (err-context-invalidation).
 * Settings sync via chrome.storage.onChanged instead of push messages —
 * eliminates the broadcast-to-all-tabs antipattern in the background SW.
 * Guard teardown/re-activation on settings change.
 * All chrome.runtime.sendMessage calls are wrapped in isAlive() checks.
 */

import { runFullDetection, collectFingerprint } from '@supersayan/detection-engine';
import {
  activateMSTIShield,
  scanForAIAgents,
  activateGPUCacheGuard,
  activateGPUPrivacyGuard,
  protectWebRTCLeaks,
  verifyToolIntegrity,
  activateSessionGuard,
  activateElicitationGuard,
  activateAbortExecutionGuard,
  activateDeclarativeFormGuard,
  activateCSSKeyGuard,
  activateQUICReplayGuard,
  activateSupplyChainGuard,
} from '@supersayan/defensive-shield';
import type { GlowMessage, GlowScanResult, GlowSettings, GlowShieldStatus } from './types';
import { DEFAULT_SETTINGS } from './types';

// ── Orphan detection ──────────────────────────────────────────────────────────
// After an extension update, chrome.runtime.id becomes undefined in the old
// content script instance. Guard every chrome.runtime call with this check.
function isAlive(): boolean {
  try {
    return !!chrome.runtime?.id;
  } catch {
    return false;
  }
}

// ── Guard lifecycle handles ────────────────────────────────────────────────────
let cleanupFns: Array<() => void> = [];
let activeSettings: GlowSettings = DEFAULT_SETTINGS;

function teardownGuards(): void {
  for (const fn of cleanupFns) {
    try { fn(); } catch { /* ignore errors during teardown */ }
  }
  cleanupFns = [];
}

function activateGuards(guards: GlowSettings['guards']): void {
  teardownGuards();

  if (guards.msti) {
    const r = activateMSTIShield();
    const c = (r as { cleanup?: () => void }).cleanup;
    if (typeof c === 'function') cleanupFns.push(c);
  }
  if (guards.gpu) {
    const r = activateGPUCacheGuard();
    const c = (r as { cleanup?: () => void }).cleanup;
    if (typeof c === 'function') cleanupFns.push(c);
    activateGPUPrivacyGuard();
  }
  if (guards.webrtc) {
    protectWebRTCLeaks();
  }
  if (guards.session) {
    const r = activateSessionGuard();
    const c = (r as { cleanup?: () => void }).cleanup;
    if (typeof c === 'function') cleanupFns.push(c);
  }
  if (guards.elicitation) {
    activateElicitationGuard();
  }
  if (guards.abortExecution) {
    activateAbortExecutionGuard();
  }
  if (guards.declForm) {
    activateDeclarativeFormGuard();
  }
  if (guards.quicReplay) {
    activateQUICReplayGuard();
  }
  if (guards.cssKey) {
    activateCSSKeyGuard();
  }
  if (guards.supplyChain) {
    activateSupplyChainGuard();
  }
}

// ── Settings sync via chrome.storage.onChanged ────────────────────────────────
// Reacts to settings saved by the background/options page without requiring
// a push message broadcast to every tab.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.glowSettings) return;
  const newSettings = changes.glowSettings.newValue as GlowSettings | undefined;
  if (!newSettings) return;
  const prevGuards = activeSettings.guards;
  activeSettings = newSettings;
  // Re-activate guards if guard config changed
  const guardsChanged = JSON.stringify(prevGuards) !== JSON.stringify(newSettings.guards);
  if (guardsChanged) {
    activateGuards(activeSettings.guards);
  }
});

// ── Build GlowShieldStatus ────────────────────────────────────────────────────
function buildShieldStatus(guards: GlowSettings['guards']): GlowShieldStatus {
  const g = (enabled: boolean): 'active' | 'inactive' => (enabled ? 'active' : 'inactive');
  return {
    msti:          g(guards.msti),
    aiAgent:       g(guards.aiAgent),
    webrtc:        g(guards.webrtc),
    toolIntegrity: g(guards.toolIntegrity),
    session:       g(guards.session),
    gpu:           g(guards.gpu),
    elicitation:   g(guards.elicitation),
    supplyChain:   g(guards.supplyChain),
    quicReplay:    g(guards.quicReplay),
    cssKey:        g(guards.cssKey),
    abortExecution: g(guards.abortExecution),
    declForm:      g(guards.declForm),
  };
}

// ── Run full detection ─────────────────────────────────────────────────────────
async function runScan(): Promise<GlowScanResult> {
  const detectionResult = runFullDetection();
  const fp = collectFingerprint();

  let aiAgentAlerts = 0;
  if (activeSettings.guards.aiAgent) {
    const agentRadar = scanForAIAgents();
    aiAgentAlerts = agentRadar.detections.length;
  }

  let toolIntegrityOk = true;
  if (activeSettings.guards.toolIntegrity) {
    const ti = verifyToolIntegrity();
    toolIntegrityOk = ti.passed;
  }

  let threatLevel = detectionResult.threatLevel;
  let overallScore = detectionResult.overallScore;

  if (aiAgentAlerts > 0) {
    overallScore = Math.min(100, overallScore + aiAgentAlerts * 12);
    if (overallScore >= 75) threatLevel = 'HIGH';
    else if (overallScore >= 50) threatLevel = 'MEDIUM';
  }
  if (!toolIntegrityOk) {
    overallScore = Math.min(100, overallScore + 20);
    if (overallScore >= 75) threatLevel = 'HIGH';
  }

  const shieldStatus = buildShieldStatus(activeSettings.guards);

  const result: GlowScanResult = {
    tabId: -1, // filled in by background on receipt
    url: window.location.href,
    timestamp: Date.now(),
    threatLevel,
    overallScore,
    signals: detectionResult.signals.map(s => ({
      id: s.id,
      category: s.category,
      name: s.name,
      passed: s.passed,
      weight: s.weight,
      details: s.details,
    })),
    shieldStatus: {
      ...shieldStatus,
      aiAgent:       aiAgentAlerts > 0    ? 'alert' : shieldStatus.aiAgent,
      toolIntegrity: !toolIntegrityOk     ? 'alert' : shieldStatus.toolIntegrity,
    },
    fingerprint: {
      userAgent:           fp.userAgent,
      platform:            fp.platform,
      hardwareConcurrency: fp.hardwareConcurrency,
      language:            fp.language,
      webglRenderer:       fp.webglRenderer,
      webglVendor:         fp.webglVendor,
      isHeadless:          fp.userAgent.toLowerCase().includes('headless'),
      hasWebGL:            !!fp.webglRenderer,
    },
    recommendations: detectionResult.recommendations,
  };

  return result;
}

// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message: GlowMessage, _sender, sendResponse) => {
  if (!isAlive()) {
    sendResponse({ ok: false, error: 'Extension context invalidated — please reload' });
    return false;
  }

  if (message.type === 'SCAN_REQUEST') {
    runScan()
      .then(result => {
        if (!isAlive()) return;
        chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result } satisfies GlowMessage)
          .catch(() => { /* background or popup may be closed */ });
        sendResponse({ ok: true });
      })
      .catch((err: unknown) => {
        sendResponse({ ok: false, error: String(err) });
      });
    return true; // keep channel open for async
  }

  return false;
});

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function bootstrap(): Promise<void> {
  if (!isAlive()) return;

  // Load persisted settings from local storage
  try {
    const stored = await chrome.storage.local.get('glowSettings');
    if (stored.glowSettings) {
      activeSettings = stored.glowSettings as GlowSettings;
    }
  } catch { /* storage not available in this context */ }

  // Activate all enabled guards immediately
  activateGuards(activeSettings.guards);

  // Auto-scan if enabled
  if (activeSettings.autoScan && isAlive()) {
    try {
      const result = await runScan();
      if (isAlive()) {
        chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result } satisfies GlowMessage)
          .catch(() => { /* background may not be ready */ });
      }
    } catch { /* scan failed — non-fatal */ }
  }
}

bootstrap();
