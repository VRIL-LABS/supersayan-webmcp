/**
 * Glow — Shared types for message passing between popup, content, background
 */

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface GlowScanResult {
  tabId: number;
  url: string;
  timestamp: number;
  threatLevel: ThreatLevel;
  overallScore: number;
  signals: GlowSignal[];
  shieldStatus: GlowShieldStatus;
  fingerprint: GlowFingerprint;
  recommendations: string[];
}

export interface GlowSignal {
  id: string;
  category: string;
  name: string;
  passed: boolean;
  weight: number;
  details: string;
}

export interface GlowShieldStatus {
  msti: GuardStatus;
  aiAgent: GuardStatus;
  webrtc: GuardStatus;
  toolIntegrity: GuardStatus;
  session: GuardStatus;
  gpu: GuardStatus;
  elicitation: GuardStatus;
  supplyChain: GuardStatus;
  quicReplay: GuardStatus;
  cssKey: GuardStatus;
  abortExecution: GuardStatus;
  declForm: GuardStatus;
}

export type GuardStatus = 'active' | 'inactive' | 'alert' | 'blocked';

export interface GlowFingerprint {
  userAgent: string;
  platform: string;
  hardwareConcurrency: number;
  language: string;
  webglRenderer: string;
  webglVendor: string;
  isHeadless: boolean;
  hasWebGL: boolean;
}

export interface GlowSettings {
  autoScan: boolean;
  badge: boolean;
  notifyHigh: boolean;
  storeHistory: boolean;
  guards: {
    msti: boolean;
    aiAgent: boolean;
    webrtc: boolean;
    toolIntegrity: boolean;
    session: boolean;
    gpu: boolean;
    elicitation: boolean;
    supplyChain: boolean;
    quicReplay: boolean;
    cssKey: boolean;
    abortExecution: boolean;
    declForm: boolean;
  };
}

export const DEFAULT_SETTINGS: GlowSettings = {
  autoScan: true,
  badge: true,
  notifyHigh: true,
  storeHistory: true,
  guards: {
    msti: true,
    aiAgent: true,
    webrtc: true,
    toolIntegrity: true,
    session: true,
    gpu: true,
    elicitation: true,
    supplyChain: true,
    quicReplay: true,
    cssKey: true,
    abortExecution: true,
    declForm: true,
  },
};

// Message types for chrome.runtime.sendMessage
export type GlowMessage =
  | { type: 'SCAN_REQUEST'; tabId?: number }
  | { type: 'SCAN_RESULT'; result: GlowScanResult }
  | { type: 'GET_LAST_RESULT'; tabId: number }
  | { type: 'LAST_RESULT_RESPONSE'; result: GlowScanResult | null }
  | { type: 'GET_SETTINGS' }
  | { type: 'SETTINGS_RESPONSE'; settings: GlowSettings }
  | { type: 'UPDATE_SETTINGS'; settings: Partial<GlowSettings> }
  | { type: 'SETTINGS_UPDATED' }
  | { type: 'CLEAR_HISTORY' }
  | { type: 'GET_HISTORY' }
  | { type: 'HISTORY_RESPONSE'; history: GlowScanResult[] };
