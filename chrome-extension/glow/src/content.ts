/**
 * Glow — Content Script
 * Runs in-page context. Imports the full SuperSayanMCP defensive + detection suite,
 * activates all guards, performs detection on demand, and posts results to the
 * background service worker.
 */

import { runFullDetection, collectFingerprint } from '@supersayan/detection-engine';
import {
  activateMSTIShield,
  scanForAIAgents,
  activateGPUCacheGuard,
  protectWebRTCLeaks,
  verifyToolIntegrity,
  activateSessionGuard,
  activateElicitationGuard,
  activateAbortExecutionGuard,
  activateDeclarativeFormGuard,
  activateGPUPrivacyGuard,
  activateQUICReplayGuard,
  activateCSSKeyGuard,
  activateSupplyChainGuard,
} from '@supersayan/defensive-shield';
import type { GlowMessage, GlowScanResult, GlowSettings, GlowShieldStatus } from './types';
import { DEFAULT_SETTINGS } from './types';

// ── Guard lifecycle handles ────────────────────────────────────────────────────

let cleanupFns: Array<() => void> = [];
let activeSettings: GlowSettings = DEFAULT_SETTINGS;

function teardownGuards() {
  cleanupFns.forEach(fn => { try { fn(); } catch { /* ignore */ } });
  cleanupFns = [];
}

function activateGuards(settings: GlowSettings['guards']) {
  teardownGuards();

  if (settings.msti) {
    const r = activateMSTIShield();
    if (typeof r.cleanup === 'function') cleanupFns.push(r.cleanup);
  }
  if (settings.gpu) {
    const r = activateGPUCacheGuard();
    if (typeof (r as { cleanup?: () => void }).cleanup === 'function') {
      cleanupFns.push((r as { cleanup: () => void }).cleanup);
    }
    activateGPUPrivacyGuard();
  }
  if (settings.webrtc) {
    protectWebRTCLeaks();
  }
  if (settings.session) {
    const r = activateSessionGuard();
    if (typeof (r as { cleanup?: () => void }).cleanup === 'function') {
      cleanupFns.push((r as { cleanup: () => void }).cleanup);
    }
  }
  if (settings.elicitation) {
    activateElicitationGuard();
  }
  if (settings.abortExecution) {
    activateAbortExecutionGuard();
  }
  if (settings.declForm) {
    activateDeclarativeFormGuard();
  }
  if (settings.quicReplay) {
    activateQUICReplayGuard();
  }
  if (settings.cssKey) {
    activateCSSKeyGuard();
  }
  if (settings.supplyChain) {
    activateSupplyChainGuard();
  }
}

// ── Build a GlowShieldStatus from enabled settings ───────────────────────────

function buildShieldStatus(settings: GlowSettings['guards']): GlowShieldStatus {
  const g = (enabled: boolean) => (enabled ? 'active' : 'inactive') as const;
  return {
    msti: g(settings.msti),
    aiAgent: g(settings.aiAgent),
    webrtc: g(settings.webrtc),
    toolIntegrity: g(settings.toolIntegrity),
    session: g(settings.session),
    gpu: g(settings.gpu),
    elicitation: g(settings.elicitation),
    supplyChain: g(settings.supplyChain),
    quicReplay: g(settings.quicReplay),
    cssKey: g(settings.cssKey),
    abortExecution: g(settings.abortExecution),
    declForm: g(settings.declForm),
  };
}

// ── Run full detection + optional ai-agent radar ──────────────────────────────

async function runScan(): Promise<GlowScanResult> {
  const detectionResult = runFullDetection();
  const fp = collectFingerprint();

  // AI Agent radar (runs fresh each scan)
  let aiAgentAlerts = 0;
  if (activeSettings.guards.aiAgent) {
    const agentRadar = scanForAIAgents();
    aiAgentAlerts = agentRadar.detections.length;
  }

  // Tool integrity
  let toolIntegrityOk = true;
  if (activeSettings.guards.toolIntegrity) {
    const ti = verifyToolIntegrity();
    toolIntegrityOk = ti.passed;
  }

  const shieldStatus = buildShieldStatus(activeSettings.guards);

  // Escalate threat if ai agent or tool integrity fires
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

  const result: GlowScanResult = {
    tabId: -1, // filled in by background
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
      aiAgent: aiAgentAlerts > 0 ? 'alert' : shieldStatus.aiAgent,
      toolIntegrity: !toolIntegrityOk ? 'alert' : shieldStatus.toolIntegrity,
    },
    fingerprint: {
      userAgent: fp.userAgent,
      platform: fp.platform,
      hardwareConcurrency: fp.hardwareConcurrency,
      language: fp.language,
      webglRenderer: fp.webglRenderer,
      webglVendor: fp.webglVendor,
      isHeadless: fp.userAgent.toLowerCase().includes('headless'),
      hasWebGL: !!fp.webglRenderer,
    },
    recommendations: detectionResult.recommendations,
  };

  return result;
}

// ── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (message: GlowMessage, _sender, sendResponse) => {
    if (message.type === 'SCAN_REQUEST') {
      runScan().then(result => {
        const msg: GlowMessage = { type: 'SCAN_RESULT', result };
        chrome.runtime.sendMessage(msg).catch(() => { /* popup may be closed */ });
        sendResponse({ ok: true });
      }).catch(err => {
        sendResponse({ ok: false, error: String(err) });
      });
      return true; // keep channel open for async
    }

    if (message.type === 'UPDATE_SETTINGS') {
      const incoming = (message as { type: 'UPDATE_SETTINGS'; settings: Partial<GlowSettings> }).settings;
      activeSettings = { ...activeSettings, ...incoming };
      if (incoming.guards) {
        activateGuards(activeSettings.guards);
      }
      sendResponse({ ok: true });
      return false;
    }

    return false;
  }
);

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function bootstrap() {
  // Load persisted settings
  try {
    const stored = await chrome.storage.local.get('glowSettings');
    if (stored.glowSettings) {
      activeSettings = stored.glowSettings as GlowSettings;
    }
  } catch { /* storage not available in this context */ }

  // Activate all enabled guards immediately
  activateGuards(activeSettings.guards);

  // Auto-scan if enabled
  if (activeSettings.autoScan) {
    const result = await runScan();
    const msg: GlowMessage = { type: 'SCAN_RESULT', result };
    try {
      chrome.runtime.sendMessage(msg);
    } catch { /* background may not be ready yet */ }
  }
}

bootstrap();
