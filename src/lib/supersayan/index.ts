export type { DetectionResult, DetectionSignal, ThreatLevel, BrowserFingerprint, WebMCPAnalysis, MCPCVE } from './detection-engine';
export { runFullDetection, startBehavioralTracking, collectFingerprint, analyzeWebMCP, getThreatColor, getThreatLabel, MCP_CVE_DATABASE } from './detection-engine';
export type { AttributionReport, OSINTTraceResult, RiskFactor } from './osint-tracer';
export { generateAttributionReport, KNOWN_DATACENTER_ASNS } from './osint-tracer';
export type { MSTIInjectionStep, MSTIDetectedToolChange, MSTISimulationResult, AISessionInfo, AISessionDetectionResult, CovertChannelDemoStep, CovertChannelResult, LeakedIP, WebRTCLeakResult, QUICFeatureImportance, QUICFingerprintResult, ToolDefinition, ToolPoisoningResult, ZeroRTTAttackStep, ZeroRTTResult, SWPersistStep, SWPersistResult, GPUAdapterFingerprint, GPUAgentProxyResult, DomClobberResult, ExtBridgeResult, AnnotationConfusionResult, CSSKeyMCPResult, QUICMCPReplayResult, AudioMCPFingerprintResult, MCPSupplyChainResult, ElicitPhishStep, ElicitPhishResult, AbortRaceStep, AbortRaceResult, DeclFormHijackStep, DeclFormHijackResult, ClientInvertStep, ClientInvertResult, ComposeXorStep, ComposeXorResult, ObserveOracleStep, ObserveOracleResult, OffensiveAnalysisResult } from './offensive-engine';
export { simulateMSTI, detectAISessions, demonstrateWebGPUCovertChannel, scanWebRTCLeaks, simulateQUICFingerprinting, demonstrateToolPoisoning, simulate0RTTReplay, simulateElicitPhish, simulateAbortRace, simulateDeclFormHijack, simulateClientInvert, simulateComposeXor, simulateObserveOracle, runOffensiveAnalysis } from './offensive-engine';

// Defensive Shield — real-time countermeasures
export type {
  ShieldThreatLevel,
  MSTIChangeLogEntry,
  MSTIShieldStatus,
  AIAgentDetection,
  AIAgentRadarResult,
  GPUCacheGuardStatus,
  WebRTCProtectionResult,
  QUICExposureResult,
  SuspiciousTool,
  ToolIntegrityResult,
  SessionAlert,
  SessionGuardStatus,
  ElicitationGuardStatus,
  AbortExecutionGuardStatus,
  DeclarativeFormGuardStatus,
  ClientReferenceGuardStatus,
  ToolCompositionGuardStatus,
  ObservationHardeningStatus,
  FullShieldStatus,
} from './defensive-shield';
export {
  activateMSTIShield,
  scanForAIAgents,
  activateGPUCacheGuard,
  protectWebRTCLeaks,
  analyzeQUICExposure,
  verifyToolIntegrity,
  activateSessionGuard,
  activateElicitationGuard,
  activateAbortExecutionGuard,
  activateDeclarativeFormGuard,
  activateClientReferenceGuard,
  activateToolCompositionGuard,
  activateObservationHardening,
  activateFullShield,
} from './defensive-shield';
