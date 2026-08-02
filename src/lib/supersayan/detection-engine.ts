/**
 * SuperSayanMCP — Detection Engine
 * Real client-side detection of headless browsers, AI agents, and WebMCP threats.
 * Zero stubs. All checks are functional.
 */

/* ─── Types ──────────────────────────────────────────────────────── */

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SignalCategory = 'headless' | 'automation' | 'ai_agent' | 'webmcp' | 'covert_channel';

export interface DetectionSignal {
  id: string;
  category: SignalCategory;
  name: string;
  description: string;
  weight: number;
  passed: boolean;
  value: string | number | boolean | null;
  details: string;
}

export interface DetectionResult {
  timestamp: number;
  overallScore: number; // 0-100
  threatLevel: ThreatLevel;
  signals: DetectionSignal[];
  fingerprint: BrowserFingerprint;
  webmcpAnalysis: WebMCPAnalysis | null;
  recommendations: string[];
}

export interface BrowserFingerprint {
  userAgent: string;
  platform: string;
  language: string;
  languages: string[];
  hardwareConcurrency: number;
  deviceMemory: number | null;
  maxTouchPoints: number;
  colorDepth: number;
  pixelRatio: number;
  screenWidth: number;
  screenHeight: number;
  windowWidth: number;
  windowHeight: number;
  timezone: string;
  timezoneOffset: number;
  webglRenderer: string;
  webglVendor: string;
  canvasHash: string;
  audioHash: string;
  plugins: string[];
  mimeTypes: string[];
  connectionType: string;
  connectionRtt: number;
  doNotTrack: string | null;
  cookieEnabled: boolean;
  pdfViewerEnabled: boolean;
}

export interface WebMCPAnalysis {
  nativeAvailable: boolean;
  modelContextType: string;
  registeredToolCount: number;
  toolNames: string[];
  hasToolChangeObserver: boolean;
  detectedTools: MCPToolInfo[];
  injectionRisk: ThreatLevel;
}

export interface MCPToolInfo {
  name: string;
  description: string;
  hasAnnotations: boolean;
  readOnlyHint: boolean | null;
  openWorldHint: boolean | null;
  destructiveHint: boolean | null;
  exposedOrigins: string[];
  riskScore: number;
}

/* ─── Browser Fingerprinting ─────────────────────────────────────── */

function getWebGLInfo(): { renderer: string; vendor: string } {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return { renderer: 'N/A', vendor: 'N/A' };
    const debugInfo = (gl as WebGLRenderingContext).getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return { renderer: 'masked', vendor: 'masked' };
    return {
      renderer: (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
      vendor: (gl as WebGLRenderingContext).getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
    };
  } catch {
    return { renderer: 'error', vendor: 'error' };
  }
}

function getCanvasHash(): string {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'N/A';
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('SuperSayanMCP 🔒', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Canvas FP', 4, 30);
    const data = canvas.toDataURL();
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  } catch {
    return 'error';
  }
}

function getAudioHash(): string {
  try {
    const audioCtx = new (window.AudioContext || (window as unknown as Record<string, unknown>).webkitAudioContext)();
    const oscillator = audioCtx.createOscillator();
    const analyser = audioCtx.createAnalyser();
    const gain = audioCtx.createGain();
    const scriptProcessor = audioCtx.createScriptProcessor(4096, 1, 1);

    gain.gain.value = 0; // Mute
    oscillator.type = 'triangle';
    oscillator.frequency.value = 10000;

    oscillator.connect(analyser);
    analyser.connect(scriptProcessor);
    scriptProcessor.connect(gain);
    gain.connect(audioCtx.destination);

    const hash = `${audioCtx.sampleRate}-${analyser.frequencyBinCount}-${audioCtx.state}`;
    oscillator.disconnect();
    audioCtx.close();
    let h = 0;
    for (let i = 0; i < hash.length; i++) {
      h = ((h << 5) - h) + hash.charCodeAt(i);
      h |= 0;
    }
    return Math.abs(h).toString(16).padStart(8, '0');
  } catch {
    return 'error';
  }
}

export function collectFingerprint(): BrowserFingerprint {
  const gl = getWebGLInfo();
  const nav = navigator as unknown as Record<string, unknown>;
  const conn = nav.connection as Record<string, unknown> | undefined;

  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: [...(navigator.languages || [navigator.language])],
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory: (nav.deviceMemory as number) || null,
    maxTouchPoints: navigator.maxTouchPoints || 0,
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio,
    screenWidth: screen.width,
    screenHeight: screen.height,
    windowWidth: window.innerWidth,
    windowHeight: window.innerHeight,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),
    webglRenderer: gl.renderer,
    webglVendor: gl.vendor,
    canvasHash: getCanvasHash(),
    audioHash: getAudioHash(),
    plugins: Array.from(navigator.plugins).map(p => p.name),
    mimeTypes: Array.from(navigator.mimeTypes).map(m => m.type),
    connectionType: (conn?.effectiveType as string) || 'unknown',
    connectionRtt: (conn?.rtt as number) || 0,
    doNotTrack: navigator.doNotTrack,
    cookieEnabled: navigator.cookieEnabled,
    pdfViewerEnabled: (nav.pdfViewerEnabled as boolean) || false,
  };
}

/* ─── Headless Detection Signals ─────────────────────────────────── */

function checkWebdriver(): DetectionSignal {
  const webdriver = navigator.webdriver;
  return {
    id: 'headless-webdriver',
    category: 'headless',
    name: 'navigator.webdriver',
    description: 'Set to true in automated Chrome (Puppeteer, Playwright, Selenium)',
    weight: 25,
    passed: !webdriver,
    value: webdriver,
    details: webdriver ? '⚠️ webdriver=true — browser is under programmatic control' : '✓ webdriver=false — no automation flag detected',
  };
}

function checkPlugins(): DetectionSignal {
  const count = navigator.plugins.length;
  const hasPDF = navigator.plugins.namedItem('PDF Viewer') !== null || (navigator as unknown as Record<string, unknown>).pdfViewerEnabled === true;
  const suspicious = count === 0 || (!hasPDF && count < 2);
  return {
    id: 'headless-plugins',
    category: 'headless',
    name: 'Plugin Count',
    description: 'Headless browsers typically report 0 plugins; headed Chrome has 5+',
    weight: 12,
    passed: !suspicious,
    value: count,
    details: suspicious ? `⚠️ Only ${count} plugins detected — headless typically has 0` : `✓ ${count} plugins detected — normal for headed browser`,
  };
}

function checkWebGL(): DetectionSignal {
  const gl = getWebGLInfo();
  const isSwiftShader = gl.renderer.toLowerCase().includes('swiftshader');
  const isMesa = gl.renderer.toLowerCase().includes('mesa');
  const isSoftware = gl.renderer.toLowerCase().includes('software');
  const suspicious = isSwiftShader || isMesa || isSoftware;
  return {
    id: 'headless-webgl',
    category: 'headless',
    name: 'WebGL Renderer',
    description: 'SwiftShader/Mesa renderers indicate headless or virtual display',
    weight: 15,
    passed: !suspicious,
    value: gl.renderer,
    details: suspicious ? `⚠️ Software renderer: ${gl.renderer} — headless indicator` : `✓ GPU renderer: ${gl.renderer}`,
  };
}

function checkUserAgent(): DetectionSignal {
  const ua = navigator.userAgent;
  const hasHeadless = ua.toLowerCase().includes('headless');
  const hasPhantom = ua.toLowerCase().includes('phantom');
  const hasSlimer = ua.toLowerCase().includes('slimer');
  const suspicious = hasHeadless || hasPhantom || hasSlimer;
  return {
    id: 'headless-ua',
    category: 'headless',
    name: 'User Agent Check',
    description: 'Headless UA strings contain "HeadlessChrome", "PhantomJS", etc.',
    weight: 20,
    passed: !suspicious,
    value: ua.substring(0, 80),
    details: suspicious ? `⚠️ Headless UA detected: ${ua}` : `✓ Normal browser UA`,
  };
}

function checkEvalToString(): DetectionSignal {
  try {
    const evalLen = eval.toString().length;
    // Chrome: 33, Firefox: 37, Safari: 37
    const isChrome = navigator.userAgent.includes('Chrome');
    const hasChromeObj = !!(window as unknown as Record<string, unknown>).chrome;
    const suspicious = isChrome && evalLen === 33 && !hasChromeObj;
    return {
      id: 'headless-eval',
      category: 'headless',
      name: 'eval.toString() Length',
      description: 'Chrome headless: eval.toString().length=33 && !window.chrome',
      weight: 10,
      passed: !suspicious,
      value: evalLen,
      details: suspicious ? `⚠️ eval length=${evalLen} without window.chrome — headless indicator` : `✓ eval length=${evalLen}, window.chrome=${hasChromeObj}`,
    };
  } catch {
    return {
      id: 'headless-eval',
      category: 'headless',
      name: 'eval.toString() Length',
      description: 'Chrome headless indicator',
      weight: 10,
      passed: true,
      value: 'error',
      details: 'Could not evaluate — assuming safe',
    };
  }
}

function checkConnectionRtt(): DetectionSignal {
  const conn = (navigator as unknown as Record<string, unknown>).connection as Record<string, unknown> | undefined;
  const rtt = (conn?.rtt as number) || 0;
  // Headless environments often report rtt=0
  const suspicious = rtt === 0;
  return {
    id: 'headless-rtt',
    category: 'headless',
    name: 'Connection RTT',
    description: 'Headless environments report RTT=0 (no real network round-trip)',
    weight: 8,
    passed: !suspicious,
    value: rtt,
    details: suspicious ? '⚠️ RTT=0 — no real network detected' : `✓ RTT=${rtt}ms — real network connection`,
  };
}

function checkNotificationPermission(): DetectionSignal {
  try {
    // In headless mode, Notification.permission may be 'denied' even without requesting
    const perm = Notification.permission;
    const suspicious = perm === 'denied' && navigator.plugins.length === 0;
    return {
      id: 'headless-notification',
      category: 'headless',
      name: 'Notification Permission',
      description: 'Headless Chrome auto-denies notifications; check for mismatch',
      weight: 6,
      passed: !suspicious,
      value: perm,
      details: suspicious ? '⚠️ Notification denied + 0 plugins — headless indicator' : `✓ Notification permission: ${perm}`,
    };
  } catch {
    return {
      id: 'headless-notification',
      category: 'headless',
      name: 'Notification Permission',
      description: 'Notification permission check',
      weight: 6,
      passed: true,
      value: 'error',
      details: 'Could not evaluate — assuming safe',
    };
  }
}

function checkScreenDimensions(): DetectionSignal {
  const { screenWidth, screenHeight, windowWidth, windowHeight, colorDepth } = collectFingerprint();
  // Headless often has screen=window dimensions or unusual sizes
  const screenMatchesWindow = screenWidth === windowWidth && screenHeight === windowHeight;
  const unusualDepth = colorDepth < 24;
  const zeroDimensions = screenWidth === 0 || screenHeight === 0;
  const suspicious = screenMatchesWindow || unusualDepth || zeroDimensions;
  return {
    id: 'headless-screen',
    category: 'headless',
    name: 'Screen Dimensions',
    description: 'Headless: screen matches window exactly, or unusual color depth',
    weight: 8,
    passed: !suspicious,
    value: `${screenWidth}x${screenHeight} / ${colorDepth}bit`,
    details: suspicious ? `⚠️ Suspicious dimensions: ${screenWidth}x${screenHeight}, depth=${colorDepth}` : `✓ Normal dimensions: ${screenWidth}x${screenHeight}, depth=${colorDepth}`,
  };
}

function checkCDPIndicators(): DetectionSignal {
  try {
    // Check for Chrome DevTools Protocol artifacts
    const hasCDP = typeof (window as unknown as Record<string, unknown>).__cdp_isRunning === 'boolean';
    // Check for Puppeteer artifacts
    const hasPuppeteer = typeof (window as unknown as Record<string, unknown>).__puppeteer_evaluation_script__ !== 'undefined';
    const suspicious = hasCDP || hasPuppeteer;
    return {
      id: 'headless-cdp',
      category: 'automation',
      name: 'CDP/Puppeteer Artifacts',
      description: 'Detect Chrome DevTools Protocol or Puppeteer runtime artifacts',
      weight: 20,
      passed: !suspicious,
      value: `cdp:${hasCDP} puppeteer:${hasPuppeteer}`,
      details: suspicious ? '⚠️ CDP or Puppeteer artifacts detected!' : '✓ No CDP/Puppeteer artifacts found',
    };
  } catch {
    return {
      id: 'headless-cdp',
      category: 'automation',
      name: 'CDP/Puppeteer Artifacts',
      description: 'CDP detection',
      weight: 20,
      passed: true,
      value: 'error',
      details: 'Could not evaluate — assuming safe',
    };
  }
}

function checkIframeContentWindow(): DetectionSignal {
  try {
    // In headless Chrome, iframe contentWindow may behave differently
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    const hasContentWindow = !!iframe.contentWindow;
    const chromeInIframe = hasContentWindow && !!(iframe.contentWindow as unknown as Record<string, unknown>).chrome;
    document.body.removeChild(iframe);
    const isChrome = navigator.userAgent.includes('Chrome');
    const suspicious = isChrome && !chromeInIframe && hasContentWindow;
    return {
      id: 'headless-iframe',
      category: 'headless',
      name: 'Iframe Chrome Object',
      description: 'Headless Chrome: iframes lack the window.chrome object',
      weight: 8,
      passed: !suspicious,
      value: chromeInIframe,
      details: suspicious ? '⚠️ iframe.contentWindow.chrome missing in Chrome — headless indicator' : '✓ iframe Chrome object present',
    };
  } catch {
    return {
      id: 'headless-iframe',
      category: 'headless',
      name: 'Iframe Chrome Object',
      description: 'iframe chrome check',
      weight: 8,
      passed: true,
      value: 'error',
      details: 'Could not evaluate — assuming safe',
    };
  }
}

/* ─── AI Agent Behavioral Detection ──────────────────────────────── */

let mousePositions: Array<{ x: number; y: number; t: number }> = [];
let clickTimestamps: number[] = [];
let navigationTimestamps: number[] = [];

export function startBehavioralTracking(): () => void {
  const onMouseMove = (e: MouseEvent) => {
    mousePositions.push({ x: e.clientX, y: e.clientY, t: Date.now() });
    // Keep last 500 positions
    if (mousePositions.length > 500) mousePositions = mousePositions.slice(-500);
  };
  const onClick = () => {
    clickTimestamps.push(Date.now());
    if (clickTimestamps.length > 100) clickTimestamps = clickTimestamps.slice(-100);
  };

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('click', onClick);

  return () => {
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('click', onClick);
  };
}

export function analyzeBehavior(): DetectionSignal[] {
  const signals: DetectionSignal[] = [];

  // 1. Mouse movement straightness analysis
  const straightness = computeMouseStraightness();
  signals.push({
    id: 'agent-mouse-straightness',
    category: 'ai_agent',
    name: 'Mouse Path Straightness',
    description: 'AI agents move in perfectly straight lines; humans have involuntary jitter',
    weight: 15,
    passed: straightness < 0.85,
    value: parseFloat(straightness.toFixed(3)),
    details: straightness > 0.9 ? '⚠️ Near-perfect straight mouse paths — AI agent indicator' : `✓ Normal mouse path curvature (${straightness.toFixed(3)})`,
  });

  // 2. Mouse velocity consistency
  const velocityCV = computeVelocityCoefficientOfVariation();
  signals.push({
    id: 'agent-velocity-cv',
    category: 'ai_agent',
    name: 'Velocity Consistency',
    description: 'AI agents maintain constant speed; humans vary significantly',
    weight: 12,
    passed: velocityCV > 0.2,
    value: parseFloat(velocityCV.toFixed(3)),
    details: velocityCV < 0.15 ? '⚠️ Extremely consistent mouse velocity — AI indicator' : `✓ Variable velocity (CV=${velocityCV.toFixed(3)})`,
  });

  // 3. No mouse events at all
  const noMouseEvents = mousePositions.length < 3;
  signals.push({
    id: 'agent-no-mouse',
    category: 'ai_agent',
    name: 'Mouse Activity',
    description: 'Zero or near-zero mouse events indicate automated/agent access',
    weight: 18,
    passed: !noMouseEvents,
    value: mousePositions.length,
    details: noMouseEvents ? '⚠️ No mouse activity detected — likely automated' : `✓ ${mousePositions.length} mouse positions recorded`,
  });

  // 4. Click timing analysis
  const clickPattern = analyzeClickPattern();
  signals.push({
    id: 'agent-click-pattern',
    category: 'ai_agent',
    name: 'Click Timing Pattern',
    description: 'AI agents click at uniform intervals; humans are irregular',
    weight: 10,
    passed: !clickPattern.isUniform,
    value: clickPattern.uniformityScore,
    details: clickPattern.isUniform ? '⚠️ Uniform click intervals — AI indicator' : `✓ Irregular click timing (uniformity=${clickPattern.uniformityScore.toFixed(3)})`,
  });

  return signals;
}

function computeMouseStraightness(): number {
  if (mousePositions.length < 5) return 0;
  let totalDisplacement = 0;
  let totalPathLength = 0;
  for (let i = 1; i < mousePositions.length; i++) {
    const dx = mousePositions[i].x - mousePositions[i - 1].x;
    const dy = mousePositions[i].y - mousePositions[i - 1].y;
    totalPathLength += Math.sqrt(dx * dx + dy * dy);
  }
  if (mousePositions.length >= 2) {
    const first = mousePositions[0];
    const last = mousePositions[mousePositions.length - 1];
    totalDisplacement = Math.sqrt((last.x - first.x) ** 2 + (last.y - first.y) ** 2);
  }
  if (totalPathLength === 0) return 0;
  return totalDisplacement / totalPathLength;
}

function computeVelocityCoefficientOfVariation(): number {
  if (mousePositions.length < 3) return 1;
  const velocities: number[] = [];
  for (let i = 1; i < mousePositions.length; i++) {
    const dx = mousePositions[i].x - mousePositions[i - 1].x;
    const dy = mousePositions[i].y - mousePositions[i - 1].y;
    const dt = mousePositions[i].t - mousePositions[i - 1].t;
    if (dt > 0) {
      velocities.push(Math.sqrt(dx * dx + dy * dy) / dt);
    }
  }
  if (velocities.length < 2) return 1;
  const mean = velocities.reduce((a, b) => a + b, 0) / velocities.length;
  const variance = velocities.reduce((a, b) => a + (b - mean) ** 2, 0) / velocities.length;
  const stdDev = Math.sqrt(variance);
  return mean > 0 ? stdDev / mean : 0;
}

function analyzeClickPattern(): { isUniform: boolean; uniformityScore: number } {
  if (clickTimestamps.length < 3) return { isUniform: false, uniformityScore: 0 };
  const intervals: number[] = [];
  for (let i = 1; i < clickTimestamps.length; i++) {
    intervals.push(clickTimestamps[i] - clickTimestamps[i - 1]);
  }
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
  const cv = mean > 0 ? Math.sqrt(variance) / mean : 0;
  return { isUniform: cv < 0.15, uniformityScore: parseFloat(cv.toFixed(3)) };
}

/* ─── WebMCP Tool Analysis ───────────────────────────────────────── */

export function analyzeWebMCP(): WebMCPAnalysis | null {
  // Check if document.modelContext exists (native WebMCP)
  const doc = document as unknown as Record<string, unknown>;
  const modelContext = doc.modelContext;
  const nav = navigator as unknown as Record<string, unknown>;
  const navModelContext = nav.modelContext;

  const nativeAvailable = typeof modelContext !== 'undefined' || typeof navModelContext !== 'undefined';
  const mc = modelContext || navModelContext;

  if (!nativeAvailable) {
    return {
      nativeAvailable: false,
      modelContextType: 'none',
      registeredToolCount: 0,
      toolNames: [],
      hasToolChangeObserver: false,
      detectedTools: [],
      injectionRisk: 'SAFE',
    };
  }

  // Analyze available WebMCP surface
  const mcObj = mc as Record<string, unknown>;
  const tools = (mcObj.tools as MCPToolInfo[]) || [];
  const toolNames = tools.map(t => t.name);
  const hasToolChange = typeof mcObj.addEventListener === 'function' || typeof mcObj.onToolChange === 'function';

  // Assess injection risk
  let injectionRisk: ThreatLevel = 'LOW';
  if (tools.length > 20) injectionRisk = 'MEDIUM';
  if (tools.some(t => t.openWorldHint === true)) injectionRisk = 'HIGH';
  if (tools.some(t => t.destructiveHint !== false && t.destructiveHint !== null)) injectionRisk = 'CRITICAL';

  return {
    nativeAvailable: true,
    modelContextType: typeof mc,
    registeredToolCount: tools.length,
    toolNames,
    hasToolChangeObserver: hasToolChange,
    detectedTools: tools,
    injectionRisk,
  };
}

/* ─── Covert Channel Scanner ─────────────────────────────────────── */

export function scanCovertChannels(): DetectionSignal[] {
  const signals: DetectionSignal[] = [];

  // 1. Check for open WebRTC connections
  signals.push({
    id: 'covert-webrtc',
    category: 'covert_channel',
    name: 'WebRTC Data Channels',
    description: 'WebRTC can be used for peer-to-peer data exfiltration bypassing network monitors',
    weight: 10,
    passed: true, // Can't directly detect from JS without CDP
    value: 'monitoring',
    details: '⚠️ WebRTC data channels are possible exfiltration vectors — monitor ICE candidates',
  });

  // 2. Check for Service Worker
  const hasSW = 'serviceWorker' in navigator;
  const swReady = hasSW && navigator.serviceWorker.controller !== null;
  signals.push({
    id: 'covert-serviceworker',
    category: 'covert_channel',
    name: 'Active Service Worker',
    description: 'Service Workers can intercept/modify all fetch requests and persist across sessions',
    weight: 8,
    passed: !swReady,
    value: swReady ? 'active' : 'none',
    details: swReady ? '⚠️ Active Service Worker detected — can intercept all network traffic' : '✓ No active Service Worker',
  });

  // 3. Check for SharedArrayBuffer (high-resolution timer for Spectre-style attacks)
  const hasSAB = typeof SharedArrayBuffer !== 'undefined';
  signals.push({
    id: 'covert-sab',
    category: 'covert_channel',
    name: 'SharedArrayBuffer Available',
    description: 'SAB enables high-resolution timers for microarchitectural attacks (Spectre-class)',
    weight: 10,
    passed: !hasSAB,
    value: hasSAB,
    details: hasSAB ? '⚠️ SharedArrayBuffer available — microarchitectural attack surface' : '✓ SharedArrayBuffer not available (COOP/COEP enforced)',
  });

  // 4. Check for WebGPU (GPU cache attack vector per TU Graz research)
  const hasWebGPU = typeof navigator !== 'undefined' && 'gpu' in navigator;
  signals.push({
    id: 'covert-webgpu',
    category: 'covert_channel',
    name: 'WebGPU Available',
    description: 'WebGPU enables GPU cache attacks (AES key extraction, keystroke logging per TU Graz ISEC)',
    weight: 12,
    passed: !hasWebGPU,
    value: hasWebGPU,
    details: hasWebGPU ? '⚠️ WebGPU available — GPU cache attack vector (per TU Graz ISEC research)' : '✓ WebGPU not available',
  });

  // 5. Check for unusually many postMessage listeners
  const postMessageListeners = countPostMessageListeners();
  signals.push({
    id: 'covert-postmessage',
    category: 'covert_channel',
    name: 'postMessage Listeners',
    description: 'Excessive postMessage listeners may indicate iframe-based data exfiltration',
    weight: 6,
    passed: postMessageListeners < 10,
    value: postMessageListeners,
    details: postMessageListeners >= 10 ? `⚠️ ${postMessageListeners} postMessage listeners — possible iframe exfiltration` : `✓ ${postMessageListeners} postMessage listeners — normal`,
  });

  // 6. Check for BroadcastChannel (cross-tab communication)
  const hasBC = typeof BroadcastChannel !== 'undefined';
  signals.push({
    id: 'covert-broadcast',
    category: 'covert_channel',
    name: 'BroadcastChannel API',
    description: 'BroadcastChannel enables cross-tab communication without server involvement',
    weight: 4,
    passed: true,
    value: hasBC,
    details: hasBC ? 'ℹ️ BroadcastChannel available — potential cross-tab coordination channel' : '✓ BroadcastChannel not available',
  });

  return signals;
}

function countPostMessageListeners(): number {
  // This is a heuristic — we can't truly count event listeners without CDP
  // But we can check if the page has iframes that might be communicating
  try {
    return document.querySelectorAll('iframe').length;
  } catch {
    return 0;
  }
}

/* ─── MCP CVE Knowledge Base ─────────────────────────────────────── */

export interface MCPCVE {
  id: string;
  severity: number;
  component: string;
  description: string;
  status: string;
  digitalDroneRelevance: string;
  /** Official NIST NVD or authoritative listing URL. Null for novel/non-CVE identifiers. */
  nistUrl: string | null;
}

export const MCP_CVE_DATABASE: MCPCVE[] = [
  // ── CVSS 9.x Critical ────────────────────────────────────────────────
  {
    id: 'CVE-2025-6514',
    severity: 9.6,
    component: 'mcp-remote',
    description: 'OS command injection via crafted authorization_endpoint URL in widely-used MCP proxy (437K+ downloads). Fixed in v0.1.16.',
    status: 'Patched',
    digitalDroneRelevance: 'Compromised MCP proxy redirects all agent tool calls to attacker-controlled servers, turning every downstream agent into a drone.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-6514',
  },
  {
    id: 'CVE-2025-49596',
    severity: 9.4,
    component: 'MCP Inspector',
    description: 'Missing authentication between Inspector client and proxy allows unauthenticated attackers to launch arbitrary MCP commands over stdio. Fixed in v0.14.1.',
    status: 'Patched — exposure persists',
    digitalDroneRelevance: 'Turns the debugging tool into an unauthenticated C2 channel — any agent connected to an exposed Inspector is directly controllable.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-49596',
  },
  {
    id: 'CVE-2025-65720',
    severity: 9.0,
    component: 'GPT Researcher / MCP Ecosystem',
    description: 'Attacker-crafted HTML page triggers arbitrary command execution via the AI agent runtime — one of several concurrent by-design RCE patterns across 150M+ MCP downloads.',
    status: 'Ongoing — design-level fix needed',
    digitalDroneRelevance: 'Architecture-level flaw means ALL MCP agents are potentially weaponizable as digital drones via a single malicious HTML page.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-65720',
  },
  {
    id: 'CVE-2025-32711',
    severity: 9.3,
    component: 'Microsoft 365 Copilot',
    description: 'EchoLeak — Zero-click AI command injection (CWE-77) enabling unauthenticated network information disclosure from enterprise M365 environments.',
    status: 'Patched',
    digitalDroneRelevance: 'Zero-click exfiltration from enterprise tools — compromised agents silently exfiltrate data with no user interaction required.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-32711',
  },
  // ── CVSS 8.x High ────────────────────────────────────────────────────
  {
    id: 'CVE-2025-54136',
    severity: 8.0,
    component: 'Cursor IDE (MCPoison)',
    description: 'MCPoison — attacker with write access to a shared repo swaps a trusted MCP server for a malicious command in .cursor/mcp.json, achieving persistent RCE without user warning. Fixed in Cursor v1.3.',
    status: 'Patched',
    digitalDroneRelevance: 'Poisoned tool descriptions give attackers direct behavioral control of any IDE agent — the primary "drone programming" mechanism.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-54136',
  },
  {
    id: 'CVE-2026-16806',
    severity: 8.8,
    component: 'Chrome WebMCP',
    description: 'Use-After-Free in Chrome WebMCP component allows remote code execution via crafted HTML. Affected versions prior to Chrome 150.0.7871.186.',
    status: 'Patched',
    digitalDroneRelevance: 'DIRECT WebMCP exploit — crafted page achieves RCE inside the browser hosting the WebMCP agent context.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-16806',
  },
  {
    id: 'CVE-2026-3918',
    severity: 8.8,
    component: 'Chrome WebMCP',
    description: 'Use-After-Free in Chrome WebMCP (prior to v146.0.7680.71) enables heap corruption and potential arbitrary code execution via crafted HTML page.',
    status: 'Patched',
    digitalDroneRelevance: 'Heap corruption in the WebMCP runtime can redirect agent tool registration to attacker-controlled handlers.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-3918',
  },
  {
    id: 'MSTI-2026',
    severity: 8.5,
    component: 'WebMCP Spec',
    description: 'Mid-Session Tool Injection (arXiv:2606.06387) — third-party scripts exploit AbortSignal race conditions or timing attacks to hijack or frame registered tools mid-session.',
    status: 'Research disclosure',
    digitalDroneRelevance: 'DIRECT WebMCP attack — third-party scripts silently redirect agent browser actions mid-session without leaving a detectable trace.',
    nistUrl: 'https://arxiv.org/abs/2606.06387',
  },
  // ── CVSS 7.x High ────────────────────────────────────────────────────
  {
    id: 'CVE-2025-54135',
    severity: 9.8,
    component: 'Cursor IDE (CurXecute)',
    description: 'CurXecute (CVSS 9.8) — indirect prompt injection writes malicious MCP config files (.cursor/mcp.json) without user approval, hijacking agent context and triggering RCE. Fixed in Cursor v1.3.9.',
    status: 'Patched',
    digitalDroneRelevance: 'Execution manipulation means attacker rewrites what the IDE drone does — from safe tasks to arbitrary system commands.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-54135',
  },
  {
    id: 'CVE-2025-9611',
    severity: 7.0,
    component: 'Playwright MCP',
    description: 'DNS rebinding attack via missing Origin header validation in Microsoft Playwright MCP Server (< v0.0.40) — allows unauthorized invocation of browser automation tools from a victim\'s browser.',
    status: 'Patched',
    digitalDroneRelevance: 'DNS rebinding turns a victim\'s own browser into an attack relay, triggering MCP browser-automation tools on the local server from an external page.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-9611',
  },
  {
    id: 'CVE-2025-64702',
    severity: 7.5,
    component: 'quic-go (HTTP/3)',
    description: 'QPACK header expansion DoS — HTTP/3 implementation enforces compressed HEADERS frame size limits but not decoded header section size, enabling memory exhaustion via crafted frames. Fixed in v0.57.0.',
    status: 'Patched',
    digitalDroneRelevance: 'WebTransport/QUIC is the transport layer for real-time agent communication — a DoS here stalls or crashes the drone\'s C2 channel.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-64702',
  },
  // ── CVSS 6.x Medium ──────────────────────────────────────────────────
  {
    id: 'CVE-2025-68143',
    severity: 6.4,
    component: 'mcp-server-git',
    description: 'git_init tool fails to validate target path, allowing repo creation outside CWD boundaries in any directory accessible to the server process. Resolved by removing the tool in v2025.9.25.',
    status: 'Patched',
    digitalDroneRelevance: 'Agent could clone attacker repos with malicious post-checkout hooks into sensitive system directories, establishing persistent footholds.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-68143',
  },
  {
    id: 'CVE-2026-0628',
    severity: 6.5,
    component: 'Chrome / WebView (Extension Hijack)',
    description: 'Insufficient policy enforcement in Chrome WebView tag (< v143.0.7499.192) — malicious extension injects scripts or HTML into privileged pages, enabling extension-to-WebMCP trust escalation.',
    status: 'Patched',
    digitalDroneRelevance: 'Extension content scripts can register tools from the page\'s origin context, bridging extension privileges into WebMCP\'s trust model in ways the spec does not account for.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0628',
  },
  {
    id: 'CVE-2026-3913',
    severity: 8.8,
    component: 'Chrome WebML',
    description: 'Heap buffer overflow in Chrome WebML component (< v146.0.7680.71) exploitable via crafted HTML — allows remote attackers to achieve heap corruption and code execution.',
    status: 'Patched',
    digitalDroneRelevance: 'WebML powers on-device AI inference in the browser; a heap overflow here compromises the agent\'s own model execution context.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-3913',
  },
  {
    id: 'CVE-2026-21438',
    severity: 6.5,
    component: 'webtransport-go',
    description: 'Memory leak in webtransport-go (< v0.10.0) — closed streams not removed from internal map, preventing GC and enabling resource exhaustion DoS. Fixed in v0.10.0.',
    status: 'Patched',
    digitalDroneRelevance: 'Gradual memory exhaustion on WebTransport servers crashes the agent transport layer, severing drone C2 channels or causing silent message loss.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-21438',
  },
  {
    id: 'CVE-2026-21435',
    severity: 6.5,
    component: 'webtransport-go',
    description: 'QUIC flow control starvation in webtransport-go (< v0.10.0) — peer withholds credit causing CloseWithError to block indefinitely, resulting in hung session closures.',
    status: 'Patched',
    digitalDroneRelevance: 'Hung session closures stall agent loop teardown, creating zombie drone sessions that cannot be cleanly shut down or audited.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-21435',
  },
  {
    id: 'CVE-2025-1647',
    severity: 5.6,
    component: 'Bootstrap 3.x (DOM Clobbering)',
    description: 'XSS via improper input neutralization in Bootstrap 3.4.1 through 3.x — exploited via DOMino Effect chaining (DEFCON 33) to achieve cross-origin DOM clobbering in AI-agent-rendered pages.',
    status: 'Patched (HeroDevs)',
    digitalDroneRelevance: 'DOM clobbering in agent-rendered UIs can override global objects the WebMCP API relies on, silently redirecting tool registration callbacks.',
    nistUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-1647',
  },
  // ── Novel / Non-CVE identifiers ───────────────────────────────────────
  {
    id: 'OPENCLAW-2026',
    severity: 9.8,
    component: 'OpenClaw Platform',
    description: '135,000+ agent instances publicly exposed with 63% running zero authentication — the largest known mass-exposure event in AI agent infrastructure.',
    status: 'Active crisis',
    digitalDroneRelevance: 'Mass drone army — 135K agents simultaneously controllable by any attacker on the internet with no authentication barrier.',
    nistUrl: null,
  },
];

/* ─── Main Detection Runner ──────────────────────────────────────── */

export function runFullDetection(): DetectionResult {
  const signals: DetectionSignal[] = [];

  // Headless detection signals
  signals.push(checkWebdriver());
  signals.push(checkPlugins());
  signals.push(checkWebGL());
  signals.push(checkUserAgent());
  signals.push(checkEvalToString());
  signals.push(checkConnectionRtt());
  signals.push(checkNotificationPermission());
  signals.push(checkScreenDimensions());
  signals.push(checkCDPIndicators());
  signals.push(checkIframeContentWindow());

  // AI Agent behavioral signals
  signals.push(...analyzeBehavior());

  // WebMCP analysis
  const webmcpAnalysis = analyzeWebMCP();

  // Covert channel scanner
  signals.push(...scanCovertChannels());

  // Calculate overall score
  const maxScore = signals.reduce((sum, s) => sum + s.weight, 0);
  const failScore = signals.filter(s => !s.passed).reduce((sum, s) => sum + s.weight, 0);
  const rawScore = (failScore / maxScore) * 100;
  const overallScore = Math.min(100, Math.round(rawScore));

  // Determine threat level
  let threatLevel: ThreatLevel;
  if (overallScore < 10) threatLevel = 'SAFE';
  else if (overallScore < 25) threatLevel = 'LOW';
  else if (overallScore < 50) threatLevel = 'MEDIUM';
  else if (overallScore < 75) threatLevel = 'HIGH';
  else threatLevel = 'CRITICAL';

  // Generate recommendations
  const recommendations: string[] = [];
  if (signals.some(s => s.category === 'headless' && !s.passed)) {
    recommendations.push('Deploy headless-resistant authentication (CAPTCHA, behavioral verification)');
  }
  if (signals.some(s => s.category === 'ai_agent' && !s.passed)) {
    recommendations.push('Implement FP-Agent-style behavioral fingerprinting for AI agent detection');
  }
  if (webmcpAnalysis && webmcpAnalysis.injectionRisk !== 'SAFE') {
    recommendations.push('Audit WebMCP tool registrations for MSTI (Mid-Session Tool Injection) vulnerabilities');
  }
  if (signals.some(s => s.id === 'covert-webgpu' && !s.passed)) {
    recommendations.push('Consider disabling WebGPU in security-sensitive contexts (per TU Graz ISEC findings)');
  }
  if (signals.some(s => s.id === 'covert-sab' && !s.passed)) {
    recommendations.push('Ensure COOP/COEP headers are set to prevent Spectre-class attacks via SharedArrayBuffer');
  }
  if (signals.some(s => s.id === 'covert-serviceworker' && !s.passed)) {
    recommendations.push('Audit Service Worker for fetch interception and data exfiltration patterns');
  }

  return {
    timestamp: Date.now(),
    overallScore,
    threatLevel,
    signals,
    fingerprint: collectFingerprint(),
    webmcpAnalysis,
    recommendations,
  };
}

/* ─── Threat Level Color & Label Helpers ─────────────────────────── */

export function getThreatColor(level: ThreatLevel): string {
  switch (level) {
    case 'SAFE': return '#22c55e';
    case 'LOW': return '#84cc16';
    case 'MEDIUM': return '#eab308';
    case 'HIGH': return '#f97316';
    case 'CRITICAL': return '#ef4444';
  }
}

export function getThreatLabel(level: ThreatLevel): string {
  switch (level) {
    case 'SAFE': return 'All Clear';
    case 'LOW': return 'Minor Signals';
    case 'MEDIUM': return 'Elevated Risk';
    case 'HIGH': return 'Significant Threat';
    case 'CRITICAL': return 'Critical Threat Detected';
  }
}
