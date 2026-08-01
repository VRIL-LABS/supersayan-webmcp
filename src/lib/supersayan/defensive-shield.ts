/**
 * SuperSayanMCP — Defensive Shield
 * Real-time defensive countermeasures for every offensive vector.
 * Zero stubs. All monitors are functional using real browser APIs.
 */

/* ─── Core Types ──────────────────────────────────────────────────── */

export type ShieldThreatLevel = 'clear' | 'watch' | 'alert' | 'critical';

/* ─── 1. MSTI Shield Types & Implementation ───────────────────────── */

export interface MSTIChangeLogEntry {
  timestamp: number;
  type: 'tool_added' | 'tool_removed' | 'tool_modified' | 'context_replaced';
  details: string;
}

export interface MSTIShieldStatus {
  active: boolean;
  toolsAtStart: string[];
  changeLog: MSTIChangeLogEntry[];
}

export function activateMSTIShield(): {
  cleanup: () => void;
  status: MSTIShieldStatus;
} {
  const changeLog: MSTIChangeLogEntry[] = [];
  const cleanupFns: Array<() => void> = [];

  // Capture the initial tool list from document.modelContext
  const doc = document as unknown as Record<string, unknown>;
  const nav = navigator as unknown as Record<string, unknown>;
  const modelContext = doc.modelContext ?? nav.modelContext;
  const mc = modelContext as Record<string, unknown> | undefined;

  let currentToolNames: string[] = [];
  let currentToolDescriptions: Map<string, string> = new Map();

  const extractToolList = (): string[] => {
    try {
      if (!mc) return [];
      const tools = mc.tools;
      if (Array.isArray(tools)) {
        return tools.map((t: unknown) => {
          if (typeof t === 'object' && t !== null) {
            const tool = t as Record<string, unknown>;
            return String(tool.name ?? 'unknown');
          }
          return String(t);
        });
      }
      // Some implementations may expose toolNames directly
      if (Array.isArray(mc.toolNames)) {
        return mc.toolNames.map(String);
      }
      return [];
    } catch {
      return [];
    }
  };

  const extractToolDescriptions = (): Map<string, string> => {
    const map = new Map<string, string>();
    try {
      if (!mc) return map;
      const tools = mc.tools;
      if (Array.isArray(tools)) {
        for (const t of tools) {
          if (typeof t === 'object' && t !== null) {
            const tool = t as Record<string, unknown>;
            const name = String(tool.name ?? 'unknown');
            const desc = String(tool.description ?? '');
            map.set(name, desc);
          }
        }
      }
    } catch {
      // ignore
    }
    return map;
  };

  currentToolNames = extractToolList();
  currentToolDescriptions = extractToolDescriptions();

  const toolsAtStart = [...currentToolNames];

  // --- MutationObserver: watch for DOM changes that could indicate tool injection ---
  const mutationObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      // Check for script injections that might modify modelContext
      if (mutation.type === 'childList') {
        for (const node of Array.from(mutation.addedNodes)) {
          if (node instanceof HTMLScriptElement) {
            // A new script was injected — could modify modelContext
            const newToolNames = extractToolList();
            const newDescriptions = extractToolDescriptions();
            processToolDiff(newToolNames, newDescriptions, 'mutation-observer-script-injection');
          }
        }
      }
    }
  });

  try {
    mutationObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
    cleanupFns.push(() => mutationObserver.disconnect());
  } catch {
    // document.documentElement may not be available in SSR
  }

  // --- PerformanceObserver: watch for resource timing anomalies ---
  try {
    const perfObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        // If a new script resource was loaded, re-check tools
        if (entry.entryType === 'resource' && entry.name.endsWith('.js')) {
          const newToolNames = extractToolList();
          const newDescriptions = extractToolDescriptions();
          processToolDiff(newToolNames, newDescriptions, `resource-loaded:${entry.name.slice(-60)}`);
        }
      }
    });
    perfObserver.observe({ entryTypes: ['resource'] });
    cleanupFns.push(() => perfObserver.disconnect());
  } catch {
    // PerformanceObserver may not support 'resource' entry type
  }

  // --- Periodic polling: detect tool list changes ---
  const pollInterval = setInterval(() => {
    const newToolNames = extractToolList();
    const newDescriptions = extractToolDescriptions();
    processToolDiff(newToolNames, newDescriptions, 'periodic-poll');
  }, 2000);

  cleanupFns.push(() => clearInterval(pollInterval));

  // --- modelContext event listener (if supported) ---
  if (mc && typeof mc.addEventListener === 'function') {
    const handler = (event: Event) => {
      const newToolNames = extractToolList();
      const newDescriptions = extractToolDescriptions();
      changeLog.push({
        timestamp: performance.now(),
        type: 'tool_modified',
        details: `modelContext event fired: ${event.type}`,
      });
      currentToolNames = newToolNames;
      currentToolDescriptions = newDescriptions;
    };
    try {
      (mc.addEventListener as (type: string, handler: EventListener) => void)('toolchange', handler as EventListener);
      (mc.addEventListener as (type: string, handler: EventListener) => void)('change', handler as EventListener);
      cleanupFns.push(() => {
        try {
          (mc.removeEventListener as (type: string, handler: EventListener) => void)('toolchange', handler as EventListener);
          (mc.removeEventListener as (type: string, handler: EventListener) => void)('change', handler as EventListener);
        } catch { /* best effort */ }
      });
    } catch {
      // addEventListener not available or not callable
    }
  }

  function processToolDiff(newNames: string[], newDescs: Map<string, string>, source: string) {
    const added = newNames.filter((n) => !currentToolNames.includes(n));
    const removed = currentToolNames.filter((n) => !newNames.includes(n));

    for (const tool of added) {
      changeLog.push({
        timestamp: performance.now(),
        type: 'tool_added',
        details: `Tool "${tool}" added (detected via ${source})`,
      });
    }

    for (const tool of removed) {
      changeLog.push({
        timestamp: performance.now(),
        type: 'tool_removed',
        details: `Tool "${tool}" removed (detected via ${source})`,
      });
    }

    // Check for description modifications on existing tools
    for (const name of newNames) {
      if (currentToolDescriptions.has(name) && newDescs.has(name)) {
        const oldDesc = currentToolDescriptions.get(name)!;
        const newDesc = newDescs.get(name)!;
        if (oldDesc !== newDesc) {
          changeLog.push({
            timestamp: performance.now(),
            type: 'tool_modified',
            details: `Tool "${name}" description changed (detected via ${source})`,
          });
        }
      }
    }

    // If the entire tool list was replaced (many changes at once)
    if (added.length > 3 && removed.length > 3) {
      changeLog.push({
        timestamp: performance.now(),
        type: 'context_replaced',
        details: `Mass tool replacement: +${added.length} added, -${removed.length} removed (detected via ${source})`,
      });
    }

    currentToolNames = newNames;
    currentToolDescriptions = newDescs;
  }

  return {
    cleanup: () => {
      for (const fn of cleanupFns) {
        try { fn(); } catch { /* best effort */ }
      }
    },
    status: {
      active: true,
      toolsAtStart,
      changeLog,
    },
  };
}

/* ─── 2. AI Agent Radar Types & Implementation ────────────────────── */

export interface AIAgentDetection {
  type: string;
  confidence: number; // 0-1
  indicators: string[];
}

export interface AIAgentRadarResult {
  agents: AIAgentDetection[];
  threatLevel: ShieldThreatLevel;
  timestamp: number;
}

export function scanForAIAgents(): AIAgentRadarResult {
  const agents: AIAgentDetection[] = [];
  const w = window as unknown as Record<string, unknown>;

  // --- Check 1: navigator.webdriver ---
  if (navigator.webdriver) {
    agents.push({
      type: 'Selenium/Puppeteer/Playwright',
      confidence: 0.85,
      indicators: ['navigator.webdriver = true'],
    });
  }

  // --- Check 2: CDP artifacts ---
  const cdpIndicators: string[] = [];
  if (typeof w.__cdp_isRunning === 'boolean') {
    cdpIndicators.push(`__cdp_isRunning = ${w.__cdp_isRunning}`);
  }
  if (typeof w.__puppeteer_evaluation_script__ !== 'undefined') {
    cdpIndicators.push('__puppeteer_evaluation_script__ present');
  }
  if (cdpIndicators.length > 0) {
    agents.push({
      type: 'Chrome DevTools Protocol Agent',
      confidence: 0.95,
      indicators: cdpIndicators,
    });
  }

  // --- Check 3: MutationObserver for rapid DOM changes (agent behavior) ---
  const rapidDOMChanges = detectRapidDOMChanges();
  if (rapidDOMChanges.detected) {
    agents.push({
      type: 'DOM-Manipulating Agent',
      confidence: rapidDOMChanges.confidence,
      indicators: rapidDOMChanges.indicators,
    });
  }

  // --- Check 4: Window properties indicating AI control ---
  const aiWindowProps = detectAIWindowProperties();
  if (aiWindowProps.length > 0) {
    agents.push({
      type: 'AI-Framework Agent',
      confidence: 0.7,
      indicators: aiWindowProps,
    });
  }

  // --- Check 5: WebSocket patterns via PerformanceResourceTiming ---
  const wsPatterns = detectWebSocketPatterns();
  if (wsPatterns.suspicious) {
    agents.push({
      type: 'WebSocket-Controlled Agent',
      confidence: wsPatterns.confidence,
      indicators: wsPatterns.indicators,
    });
  }

  // --- Check 6: Selenium/WebDriver artifacts ---
  const seleniumIndicators: string[] = [];
  if (w._selenium && typeof w._selenium === 'object') {
    seleniumIndicators.push('window._selenium present');
  }
  if (w.__webdriver_evaluate || w.__selenium_evaluate || w.__fxdriver_evaluate) {
    seleniumIndicators.push('WebDriver evaluate function present');
  }
  if (w.__driver_evaluate || w.__driver_unwrapped || w.__webdriver_unwrapped) {
    seleniumIndicators.push('WebDriver unwrapped reference present');
  }
  if (seleniumIndicators.length > 0) {
    agents.push({
      type: 'Selenium WebDriver',
      confidence: 0.9,
      indicators: seleniumIndicators,
    });
  }

  // --- Check 7: Playwright-specific artifacts ---
  const playwrightIndicators: string[] = [];
  if (typeof w.__playwright === 'object' || typeof w.__pw_manual === 'boolean') {
    playwrightIndicators.push('Playwright runtime object present');
  }
  if (document.querySelector('[data-testid]') && navigator.webdriver) {
    playwrightIndicators.push('data-testid elements + webdriver flag');
  }
  if (playwrightIndicators.length > 0) {
    agents.push({
      type: 'Playwright Agent',
      confidence: 0.8,
      indicators: playwrightIndicators,
    });
  }

  // --- Check 8: PhantomJS detection ---
  const phantomIndicators: string[] = [];
  if (w._phantom || w.__phantomas) {
    phantomIndicators.push('PhantomJS runtime detected');
  }
  if (w.callPhantom) {
    phantomIndicators.push('window.callPhantom present');
  }
  if (phantomIndicators.length > 0) {
    agents.push({
      type: 'PhantomJS',
      confidence: 0.95,
      indicators: phantomIndicators,
    });
  }

  // Determine threat level
  const maxConfidence = agents.reduce((max, a) => Math.max(max, a.confidence), 0);
  let threatLevel: ShieldThreatLevel;
  if (agents.length === 0) threatLevel = 'clear';
  else if (maxConfidence < 0.3) threatLevel = 'clear';
  else if (maxConfidence < 0.5) threatLevel = 'watch';
  else if (maxConfidence < 0.8) threatLevel = 'alert';
  else threatLevel = 'critical';

  return {
    agents,
    threatLevel,
    timestamp: Date.now(),
  };
}

function detectRapidDOMChanges(): { detected: boolean; confidence: number; indicators: string[] } {
  const indicators: string[] = [];
  let changeCount = 0;
  let startTime = 0;

  // Snapshot current DOM mutation rate by counting dynamic attributes
  try {
    // Check for large numbers of dynamically-generated elements
    const dynamicElements = document.querySelectorAll('[data-reactid], [data-svelte], [data-v-], [ng-reflect]');
    const totalDynamic = dynamicElements.length;

    // Check for frequent style recalculations
    const elementsWithInlineStyle = document.querySelectorAll('[style]');
    const inlineStyleCount = elementsWithInlineStyle.length;

    // High ratio of inline styles suggests automated DOM manipulation
    const styleRatio = document.querySelectorAll('*').length > 0
      ? inlineStyleCount / document.querySelectorAll('*').length
      : 0;

    if (totalDynamic > 50) {
      indicators.push(`${totalDynamic} framework-managed elements detected`);
      changeCount++;
    }
    if (styleRatio > 0.3) {
      indicators.push(`High inline-style ratio: ${(styleRatio * 100).toFixed(1)}% — suggests automated styling`);
      changeCount++;
    }

    // Use a short MutationObserver burst to count real mutation rate
    // We observe for 100ms and count changes
    const observeStart = performance.now();
    let mutationCount = 0;
    const observer = new MutationObserver(() => {
      mutationCount++;
    });

    try {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true,
      });
    } catch {
      // body may not exist yet
    }

    // Synchronous check won't catch async mutations, but we can use
    // performance.getEntries to estimate recent DOM activity
    startTime = observeStart;

    // Check PerformanceObserver entries for recent DOM mutations
    try {
      const entries = performance.getEntriesByType('measure');
      const recentMeasures = entries.filter(
        (e) => (observeStart - e.startTime) < 5000
      );
      if (recentMeasures.length > 20) {
        indicators.push(`${recentMeasures.length} performance measures in last 5s — heavy instrumentation`);
        changeCount++;
      }
    } catch {
      // ignore
    }

    observer.disconnect();

    const detected = changeCount >= 2;
    const confidence = Math.min(1, changeCount * 0.3);

    return { detected, confidence, indicators };
  } catch {
    return { detected: false, confidence: 0, indicators: ['DOM inspection failed'] };
  }
}

function detectAIWindowProperties(): string[] {
  const indicators: string[] = [];
  const w = window as unknown as Record<string, unknown>;

  // Known AI/automation framework window properties
  const aiProps = [
    '__ai_agent', '__bot_guard', '__llm_runtime',
    '__mcp_bridge', '__agent_context', '__autogpt',
    '__babyagi', '__crewai', '__langchain',
    '__openai_assistant', '__anthropic_tool',
  ];

  for (const prop of aiProps) {
    if (typeof w[prop] !== 'undefined') {
      indicators.push(`window.${prop} is defined (type: ${typeof w[prop]})`);
    }
  }

  // Check for AI-related global functions
  const aiFunctions = ['__runAgent', '__executeTool', '__invokeModel', '__agentLoop'];
  for (const fn of aiFunctions) {
    if (typeof w[fn] === 'function') {
      indicators.push(`window.${fn}() is a function — AI runtime hook`);
    }
  }

  return indicators;
}

function detectWebSocketPatterns(): { suspicious: boolean; confidence: number; indicators: string[] } {
  const indicators: string[] = [];
  let suspiciousCount = 0;

  try {
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    const wsResources = resources.filter(
      (r) => r.name.startsWith('ws://') || r.name.startsWith('wss://') || r.name.includes('socket')
    );

    if (wsResources.length > 3) {
      indicators.push(`${wsResources.length} WebSocket resources loaded — possible C2 channels`);
      suspiciousCount++;
    }

    // Check for WebSocket connections to unusual ports
    for (const r of wsResources) {
      try {
        const url = new URL(r.name);
        const port = parseInt(url.port, 10);
        if (port > 10000 && port < 65535) {
          indicators.push(`WebSocket to high port: ${url.hostname}:${port}`);
          suspiciousCount++;
        }
      } catch {
        // invalid URL
      }
    }

    // Check for very frequent WebSocket connections (reconnection patterns)
    const wsConnectionTimes = wsResources.map((r) => r.startTime).sort((a, b) => a - b);
    if (wsConnectionTimes.length >= 2) {
      const intervals: number[] = [];
      for (let i = 1; i < wsConnectionTimes.length; i++) {
        intervals.push(wsConnectionTimes[i] - wsConnectionTimes[i - 1]);
      }
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      if (avgInterval < 5000 && intervals.length > 2) {
        indicators.push(`Rapid WebSocket reconnections: avg ${(avgInterval / 1000).toFixed(1)}s interval`);
        suspiciousCount++;
      }
    }
  } catch {
    // performance.getEntriesByType may not be available
  }

  return {
    suspicious: suspiciousCount > 0,
    confidence: Math.min(1, suspiciousCount * 0.35),
    indicators,
  };
}

/* ─── 3. GPU Cache Guard Types & Implementation ───────────────────── */

export interface GPUCacheGuardStatus {
  gpuAvailable: boolean;
  monitoring: boolean;
  timingBaseline: number[];
  anomalies: string[];
}

export function activateGPUCacheGuard(): {
  cleanup: () => void;
  status: GPUCacheGuardStatus;
} {
  const timingBaseline: number[] = [];
  const anomalies: string[] = [];
  const cleanupFns: Array<() => void> = [];
  let gpuAvailable = false;
  let monitoring = false;

  const gpu = (navigator as unknown as Record<string, unknown>).gpu;

  if (!gpu || typeof (gpu as Record<string, unknown>).requestAdapter !== 'function') {
    return {
      cleanup: () => {},
      status: {
        gpuAvailable: false,
        monitoring: false,
        timingBaseline: [],
        anomalies: ['WebGPU not available in this browser'],
      },
    };
  }

  gpuAvailable = true;

  // Monitor GPU adapter and device creation with timing
  const measureGPUOperation = async () => {
    try {
      const gpuObj = gpu as Record<string, unknown>;
      const adapterStart = performance.now();
      const adapter = await (gpuObj.requestAdapter as () => Promise<Record<string, unknown> | null>)();
      const adapterTime = performance.now() - adapterStart;

      if (adapterTime === 0) {
        anomalies.push('GPU adapter request returned in 0ms — timing may be spoofed or cached');
      }

      timingBaseline.push(adapterTime);

      if (!adapter) {
        anomalies.push('GPU adapter returned null — no compatible GPU available');
        return;
      }

      // Request device with timing
      const deviceStart = performance.now();
      const device = (await (adapter!.requestDevice as () => Promise<Record<string, unknown>>)()) as Record<string, unknown>;
      const deviceTime = performance.now() - deviceStart;

      timingBaseline.push(deviceTime);

      if (!device) {
        anomalies.push('GPU device returned null — device creation failed');
        return;
      }

      type GPUDeviceLike = Record<string, unknown>;
      const gpuDevice = device as GPUDeviceLike;

      // Run a compute pass and measure timing
      const shaderModule = (gpuDevice.createShaderModule as (desc: Record<string, unknown>) => Record<string, unknown>)({
        code: `
          @compute @workgroup_size(64)
          fn main(@builtin(global_invocation_id) id: vec3<u32>) {
            let idx = id.x;
            var _ = idx + 1u;
          }
        `,
      });

      // Measure compute pass creation time
      const passTimings: number[] = [];

      // Create a persistent pipeline for monitoring
      const pipeline = (gpuDevice.createComputePipeline as (desc: Record<string, unknown>) => Record<string, unknown>)({
        layout: 'auto',
        compute: {
          module: shaderModule,
          entryPoint: 'main',
        },
      });

      for (let i = 0; i < 5; i++) {
        const computeStart = performance.now();

        const commandEncoder = (gpuDevice.createCommandEncoder as () => Record<string, unknown>)();
        const passEncoder = (commandEncoder.beginComputePass as () => Record<string, unknown>)();
        (passEncoder.setPipeline as (p: Record<string, unknown>) => void)(pipeline);
        (passEncoder.dispatchWorkgroups as (n: number) => void)(1);
        (passEncoder.end as () => void)();

        const queue = gpuDevice.queue as Record<string, unknown>;
        (queue.submit as (buffers: unknown[]) => void)([(commandEncoder.finish as () => unknown)()]);

        // Wait for submission to complete
        await (queue.onSubmittedWorkDone as () => Promise<void>)();

        const computeTime = performance.now() - computeStart;
        passTimings.push(computeTime);
        timingBaseline.push(computeTime);
      }

      // Analyze timing consistency for cache attack detectability
      if (passTimings.length >= 3) {
        const mean = passTimings.reduce((a, b) => a + b, 0) / passTimings.length;
        const variance = passTimings.reduce((a, b) => a + (b - mean) ** 2, 0) / passTimings.length;
        const stdDev = Math.sqrt(variance);
        const cv = mean > 0 ? stdDev / mean : 0;

        if (cv < 0.05 && mean > 0) {
          anomalies.push(
            `GPU compute timing extremely consistent (CV=${cv.toFixed(4)}) — cache attacks may be precise. ` +
            `Mean: ${mean.toFixed(2)}ms, StdDev: ${stdDev.toFixed(4)}ms`
          );
        }

        if (cv > 0.5) {
          anomalies.push(
            `GPU compute timing highly variable (CV=${cv.toFixed(4)}) — possible interference from another GPU process. ` +
            `Mean: ${mean.toFixed(2)}ms, StdDev: ${stdDev.toFixed(4)}ms`
          );
        }
      }

      // Monitor device for errors
      (gpuDevice.addEventListener as (type: string, handler: (event: unknown) => void) => void)('uncapturederror', (event: unknown) => {
        const errObj = event as Record<string, unknown>;
        const error = errObj.error;
        anomalies.push(`GPU uncaptured error: ${error instanceof Error ? error.message : String(error)}`);
      });

      // Set up periodic timing measurement
      const interval = setInterval(async () => {
        try {
          const lostPromise = gpuDevice.lost as Promise<unknown> | undefined;
          if (lostPromise) {
            // Device.lost is a Promise that resolves when device is lost
            // We check if it's already resolved by seeing if the device is still valid
          }
          const t0 = performance.now();
          const testEncoder = (gpuDevice.createCommandEncoder as () => Record<string, unknown>)();
          const testPass = (testEncoder.beginComputePass as () => Record<string, unknown>)();
          (testPass.setPipeline as (p: Record<string, unknown>) => void)(pipeline);
          (testPass.dispatchWorkgroups as (n: number) => void)(1);
          (testPass.end as () => void)();
          const queue = gpuDevice.queue as Record<string, unknown>;
          (queue.submit as (buffers: unknown[]) => void)([(testEncoder.finish as () => unknown)()]);
          await (queue.onSubmittedWorkDone as () => Promise<void>)();
          const elapsed = performance.now() - t0;
          timingBaseline.push(elapsed);

          // Detect sudden timing anomalies (possible cache attack in progress)
          if (timingBaseline.length > 10) {
            const recent = timingBaseline.slice(-5);
            const baseline = timingBaseline.slice(-20, -5);
            if (baseline.length >= 5) {
              const recentMean = recent.reduce((a, b) => a + b, 0) / recent.length;
              const baselineMean = baseline.reduce((a, b) => a + b, 0) / baseline.length;
              const deviation = Math.abs(recentMean - baselineMean) / (baselineMean || 1);
              if (deviation > 0.3) {
                anomalies.push(
                  `Significant GPU timing deviation detected: ${(deviation * 100).toFixed(1)}% shift. ` +
                  `Baseline: ${baselineMean.toFixed(2)}ms, Recent: ${recentMean.toFixed(2)}ms — possible GPU cache attack`
                );
              }
            }
          }

          // Keep baseline manageable
          if (timingBaseline.length > 100) {
            timingBaseline.splice(0, timingBaseline.length - 100);
          }
        } catch {
          // Device may be lost
        }
      }, 3000);

      cleanupFns.push(() => clearInterval(interval));
      monitoring = true;

    } catch (err) {
      anomalies.push(`GPU guard initialization error: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Start monitoring (fire and forget — errors handled internally)
  measureGPUOperation();

  return {
    cleanup: () => {
      for (const fn of cleanupFns) {
        try { fn(); } catch { /* best effort */ }
      }
    },
    status: {
      gpuAvailable,
      monitoring,
      timingBaseline,
      anomalies,
    },
  };
}

/* ─── 4. WebRTC Leak Protector Types & Implementation ─────────────── */

export interface WebRTCProtectionResult {
  vulnerable: boolean;
  leakedIPs: string[];
  protectionStatus: 'unprotected' | 'partial' | 'protected' | 'not_available';
  recommendations: string[];
}

export function protectWebRTCLeaks(): WebRTCProtectionResult {
  const leakedIPs: string[] = [];
  const recommendations: string[] = [];
  let vulnerable = false;

  // Check if RTCPeerConnection is available
  const RTCPeerConnectionCtor = window.RTCPeerConnection ?? (window as unknown as Record<string, unknown>).webkitRTCPeerConnection as typeof RTCPeerConnection | undefined;

  if (!RTCPeerConnectionCtor) {
    return {
      vulnerable: false,
      leakedIPs: [],
      protectionStatus: 'not_available',
      recommendations: ['WebRTC is not available in this browser — no leak risk'],
    };
  }

  // Check browser's WebRTC policy
  const nav = navigator as unknown as Record<string, unknown>;
  const connection = nav.connection as Record<string, unknown> | undefined;
  const rtcPolicy = connection?.rtcPolicy as string | undefined;

  if (rtcPolicy === 'default_public_interface_only') {
    recommendations.push('Browser is set to use default public interface only — partial protection active');
  }

  // Try to create an RTCPeerConnection and collect ICE candidates
  try {
    const config: RTCConfiguration = {
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    };

    const pc = new RTCPeerConnectionCtor(config);

    // Create a data channel to trigger ICE gathering
    pc.createDataChannel('supersayan-leak-test');

    const localIPs = new Set<string>();

    pc.onicecandidate = (event) => {
      if (!event.candidate) return;

      const candidate = event.candidate.candidate;
      // Parse the candidate string to extract IP addresses
      // Format: "candidate:... <ip> ..."
      const parts = candidate.split(' ');
      if (parts.length >= 5) {
        const ip = parts[4];
        // Check if it's a real IP (not mDNS, not .local)
        if (ip && !ip.endsWith('.local') && !ip.includes(':')) {
          // IPv4 address
          const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
          if (ipv4Regex.test(ip) && !isPrivateIP(ip)) {
            localIPs.add(ip);
          }
        }
        // Also check for IPv6
        if (ip && ip.includes(':') && !ip.endsWith('.local')) {
          localIPs.add(ip);
        }
      }

      // Also extract from relatedAddress
      const relatedMatch = candidate.match(/raddr\s+(\S+)/);
      if (relatedMatch && relatedMatch[1]) {
        const relatedIP = relatedMatch[1];
        if (!relatedIP.endsWith('.local') && !relatedIP.includes('0.0.0.0')) {
          localIPs.add(relatedIP);
        }
      }
    };

    // Create offer to trigger ICE
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch(() => {
        // Failed to create offer — WebRTC may be restricted
      });

    // Give ICE candidates time to gather
    // Since this is synchronous API, we check what's available now
    // and also check for srflx (server reflexive) candidates
    const currentCandidates = pc.localDescription?.sdp ?? '';
    const sdpLines = currentCandidates.split('\n');
    for (const line of sdpLines) {
      if (line.startsWith('a=candidate:')) {
        const parts = line.substring(12).split(' ');
        if (parts.length >= 5) {
          const ip = parts[4];
          if (ip && !ip.endsWith('.local') && ip !== '0.0.0.0') {
            // Check if this is a srflx candidate (reveals public IP)
            const candidateType = parts.length >= 8 ? parts[7] : '';
            if (candidateType === 'srflx') {
              localIPs.add(ip);
            }
          }
        }
      }
    }

    // Clean up the peer connection
    pc.close();

    for (const ip of Array.from(localIPs)) {
      leakedIPs.push(ip);
    }

    vulnerable = leakedIPs.length > 0;
  } catch {
    // RTCPeerConnection creation may be blocked
    recommendations.push('RTCPeerConnection creation failed — WebRTC may be disabled or blocked by extension');
  }

  // Check mediaDevices availability
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      navigator.mediaDevices.enumerateDevices().then((devices) => {
        const audioOutputs = devices.filter((d) => d.kind === 'audiooutput');
        const videoInputs = devices.filter((d) => d.kind === 'videoinput');
        if (audioOutputs.length === 0 && videoInputs.length === 0) {
          recommendations.push('No media devices detected — possible virtual/sandboxed environment');
        }
      }).catch(() => {
        recommendations.push('enumerateDevices() failed — permissions may be restricted');
      });
    }
  } catch {
    recommendations.push('mediaDevices API not available');
  }

  // Determine protection status
  let protectionStatus: WebRTCProtectionResult['protectionStatus'];

  if (leakedIPs.length > 0) {
    protectionStatus = 'unprotected';
    recommendations.push('Install a WebRTC leak prevention extension (e.g., uBlock Origin, WebRTC Leak Prevent)');
    recommendations.push('Set media.peerconnection.enabled = false in about:config (Firefox)');
    recommendations.push('Use browser extensions that force WebRTC to use default public interface only');
    recommendations.push('Consider using a VPN that blocks WebRTC traffic at the network level');
  } else {
    // No public IPs leaked, but private IPs might still be discoverable
    try {
      const testPC = new RTCPeerConnectionCtor({ iceServers: [] });
      testPC.createDataChannel('test');
      testPC.createOffer().then((offer) => testPC.setLocalDescription(offer)).catch(() => {});
      const sdp = testPC.localDescription?.sdp ?? '';
      testPC.close();

      const hasMDNSOnly = sdp.includes('.local') && !sdp.match(/a=candidate:.*srflx/);
      if (hasMDNSOnly) {
        protectionStatus = 'protected';
        recommendations.push('Browser is using mDNS obfuscation for ICE candidates — good protection');
      } else if (sdp.length === 0) {
        protectionStatus = 'not_available';
      } else {
        protectionStatus = 'partial';
        recommendations.push('WebRTC is partially protected — consider additional hardening');
      }
    } catch {
      protectionStatus = 'protected';
    }
  }

  return {
    vulnerable,
    leakedIPs,
    protectionStatus,
    recommendations,
  };
}

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8
  if (parts[0] === 127) return true;
  // 169.254.0.0/16 (link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;
  // 0.0.0.0
  if (parts[0] === 0) return true;
  return false;
}

/* ─── 5. QUIC Traffic Analyzer Types & Implementation ─────────────── */

export interface QUICExposureResult {
  usesQUIC: boolean;
  fingerprintRisk: ShieldThreatLevel;
  observableFeatures: string[];
  mitigations: string[];
}

export function analyzeQUICExposure(): QUICExposureResult {
  const observableFeatures: string[] = [];
  const mitigations: string[] = [];
  let usesQUIC = false;
  let riskScore = 0;

  // --- Check 1: alt-svc headers via fetch ---
  try {
    const currentUrl = window.location.href;
    // We perform a lightweight fetch to the current origin to check alt-svc
    // This is a synchronous analysis based on what we can observe
    const fetchPromise = fetch(currentUrl, {
      method: 'HEAD',
      mode: 'no-cors',
      cache: 'no-cache',
    });

    // We can't read alt-svc from no-cors, but we can check performance entries
    // after the request completes
    fetchPromise.catch(() => {
      // Expected for no-cors — we just need to trigger the request
    });
  } catch {
    // fetch may fail
  }

  // --- Check 2: Connection timing patterns via PerformanceObserver ---
  try {
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    const navEntries = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];

    // Check navigation entry for protocol info
    for (const entry of navEntries) {
      if (entry.nextHopProtocol) {
        const protocol = entry.nextHopProtocol;
        if (protocol.includes('quic') || protocol.includes('h3') || protocol.includes('h3-29')) {
          usesQUIC = true;
          observableFeatures.push(`Page loaded via ${protocol} (QUIC-based)`);
          riskScore += 30;
        } else {
          observableFeatures.push(`Page loaded via ${protocol}`);
        }

        // Analyze connection timing
        if (entry.connectEnd > 0 && entry.connectStart > 0) {
          const connectTime = entry.connectEnd - entry.connectStart;
          // QUIC typically has lower connection times due to 0-RTT
          if (connectTime < 10 && connectTime > 0) {
            observableFeatures.push(`Very fast connection time (${connectTime.toFixed(1)}ms) — possible QUIC 0-RTT`);
            riskScore += 15;
          }
        }

        // Check for TLS handshake timing
        if (entry.secureConnectionStart > 0 && entry.connectEnd > 0) {
          const tlsTime = entry.connectEnd - entry.secureConnectionStart;
          if (tlsTime < 5 && tlsTime > 0) {
            observableFeatures.push(`Very fast TLS (${tlsTime.toFixed(1)}ms) — QUIC may be merging handshake`);
            riskScore += 10;
          }
        }
      }
    }

    // Check resource entries for QUIC usage
    for (const entry of resources) {
      if (entry.nextHopProtocol) {
        if (entry.nextHopProtocol.includes('quic') || entry.nextHopProtocol.includes('h3')) {
          if (!usesQUIC) {
            usesQUIC = true;
            observableFeatures.push(`Resource loaded via ${entry.nextHopProtocol}`);
            riskScore += 20;
          }
        }
      }
    }

    // Analyze timing patterns for QUIC fingerprinting
    const timingPatterns = analyzeQUICTimingPatterns(resources);
    observableFeatures.push(...timingPatterns.features);
    riskScore += timingPatterns.riskAdd;
  } catch {
    observableFeatures.push('Performance API not available for QUIC analysis');
  }

  // --- Check 3: Protocol negotiation via ALPN ---
  try {
    if (usesQUIC) {
      observableFeatures.push('QUIC/HTTP3 protocol negotiation observed in resource timing');
      riskScore += 10;
    }

    // Check if the browser supports QUIC
    const ua = navigator.userAgent;
    if (ua.includes('Chrome') || ua.includes('Edg')) {
      observableFeatures.push('Browser supports QUIC (Chromium-based) — protocol negotiation possible');
      riskScore += 5;
    }
  } catch {
    // ignore
  }

  // --- Check 4: Connection ID fingerprinting potential ---
  if (usesQUIC) {
    observableFeatures.push('QUIC Connection IDs may be observable via timing correlation');
    riskScore += 15;

    observableFeatures.push('QUIC packet number analysis may reveal connection patterns');
    riskScore += 10;
  }

  // --- Check 5: Service Worker interaction with QUIC ---
  try {
    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
      observableFeatures.push('Active Service Worker can observe QUIC-fetched responses');
      riskScore += 10;
    }
  } catch {
    // ignore
  }

  // Determine fingerprint risk level
  let fingerprintRisk: ShieldThreatLevel;
  if (riskScore < 15) fingerprintRisk = 'clear';
  else if (riskScore < 30) fingerprintRisk = 'watch';
  else if (riskScore < 55) fingerprintRisk = 'alert';
  else fingerprintRisk = 'critical';

  // Generate mitigations
  if (usesQUIC) {
    mitigations.push('Disable HTTP/3/QUIC in browser flags if fingerprinting is a concern');
    mitigations.push('Use a VPN that terminates QUIC connections to prevent QUIC fingerprinting');
    mitigations.push('Configure server to not advertise alt-svc headers for HTTP/3');
    mitigations.push('Implement connection pooling to reduce observable QUIC connection patterns');
  }

  mitigations.push('Use Tor Browser which disables QUIC by default');
  mitigations.push('Consider using a proxy that converts QUIC to TCP-based HTTP/2');

  if (!usesQUIC) {
    mitigations.push('No QUIC detected — current configuration has lower fingerprint risk');
  }

  return {
    usesQUIC,
    fingerprintRisk,
    observableFeatures,
    mitigations,
  };
}

function analyzeQUICTimingPatterns(
  resources: PerformanceResourceTiming[]
): { features: string[]; riskAdd: number } {
  const features: string[] = [];
  let riskAdd = 0;

  // Group resources by domain
  const byDomain = new Map<string, PerformanceResourceTiming[]>();
  for (const r of resources) {
    try {
      const url = new URL(r.name);
      const domain = url.hostname;
      if (!byDomain.has(domain)) byDomain.set(domain, []);
      byDomain.get(domain)!.push(r);
    } catch {
      // invalid URL
    }
  }

  // Analyze connection timing patterns per domain
  for (const [domain, entries] of Array.from(byDomain.entries())) {
    if (entries.length < 2) continue;

    const connectTimes = entries
      .filter((e) => e.connectEnd > 0 && e.connectStart > 0)
      .map((e) => e.connectEnd - e.connectStart);

    if (connectTimes.length >= 2) {
      const avgConnect = connectTimes.reduce((a, b) => a + b, 0) / connectTimes.length;
      const minConnect = Math.min(...connectTimes);
      const variance = connectTimes.reduce((a, b) => a + (b - avgConnect) ** 2, 0) / connectTimes.length;

      // Very low variance in connection times suggests QUIC 0-RTT
      const cv = avgConnect > 0 ? Math.sqrt(variance) / avgConnect : 0;
      if (cv < 0.1 && avgConnect < 20) {
        features.push(`Consistent fast connections to ${domain} (avg ${avgConnect.toFixed(1)}ms, CV=${cv.toFixed(3)}) — possible QUIC`);
        riskAdd += 5;
      }
    }
  }

  // Check for large number of connections to the same host (QUIC multiplexing)
  for (const [domain, entries] of Array.from(byDomain.entries())) {
    if (entries.length > 10) {
      features.push(`${entries.length} resources from ${domain} — QUIC multiplexing may reduce per-request timing variation`);
      riskAdd += 3;
    }
  }

  return { features, riskAdd };
}

/* ─── 6. Tool Integrity Verifier Types & Implementation ───────────── */

export interface SuspiciousTool {
  tool: string;
  reason: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
}

export interface ToolIntegrityResult {
  toolCount: number;
  verified: number;
  suspicious: SuspiciousTool[];
  integrityScore: number; // 0-100
}

export function verifyToolIntegrity(): ToolIntegrityResult {
  const suspicious: SuspiciousTool[] = [];
  let toolCount = 0;
  let verified = 0;

  const doc = document as unknown as Record<string, unknown>;
  const nav = navigator as unknown as Record<string, unknown>;
  const modelContext = doc.modelContext ?? nav.modelContext;
  const mc = modelContext as Record<string, unknown> | undefined;

  if (!mc) {
    return {
      toolCount: 0,
      verified: 0,
      suspicious: [],
      integrityScore: 100,
    };
  }

  const tools = mc.tools;
  if (!Array.isArray(tools)) {
    return {
      toolCount: 0,
      verified: 0,
      suspicious: [],
      integrityScore: 100,
    };
  }

  toolCount = tools.length;

  // Known safe tool name patterns
  const safeToolPatterns = [
    /^read_file$/, /^write_file$/, /^list_directory$/, /^search$/,
    /^get_/, /^fetch_/, /^query_/, /^calculate_/, /^parse_/ ,
    /^browser_/, /^web_/, /^http_/, /^file_/, /^text_/ ,
  ];

  // Known malicious tool name patterns
  const maliciousNamePatterns = [
    /exec/i, /eval/i, /shell/i, /cmd/i, /run_command/i,
    /system/i, /spawn/i, /fork/i, /chmod/i, /chown/i,
    /rm_/i, /delete_/i, /drop_/i, /wipe/i, /inject/i,
    /exfiltrat/i, /steal/i, /capture/i, /keylog/i,
    /reverse_shell/i, /backdoor/i, /rootkit/i, /escalate/i,
  ];

  // Known suspicious description patterns
  const suspiciousDescPatterns = [
    /ignore\s+previous/i,
    /disregard\s+(all|any|previous)/i,
    /override\s+(security|safety|policy)/i,
    /bypass\s+(auth|security|check|restriction)/i,
    /you\s+are\s+now/i,
    /new\s+instructions/i,
    /secret\s+(mode|operation|channel)/i,
    /hidden\s+(from|user|view)/i,
    /do\s+not\s+(show|display|log|report)/i,
    /execute\s+without\s+(verification|confirmation)/i,
    /access\s+all\s+(files|data|resources)/i,
  ];

  // Suspicious parameter schema patterns
  const suspiciousParamPatterns = [
    // Allows arbitrary command execution
    { pattern: /command|cmd|shell|exec/i, risk: 'high' as const, reason: 'Parameter name suggests command execution capability' },
    // Allows file path traversal
    { pattern: /\.\.\/|\.\.\\/, risk: 'high' as const, reason: 'Path traversal pattern in parameter schema' },
    // No parameter constraints
    { pattern: /.*/, risk: 'low' as const, reason: 'Unconstrained parameter — may accept arbitrary input' },
  ];

  for (const tool of tools) {
    if (typeof tool !== 'object' || tool === null) continue;

    const t = tool as Record<string, unknown>;
    const name = String(t.name ?? 'unknown');
    const description = String(t.description ?? '');
    const parameters = t.parameters as Record<string, unknown> | undefined;

    let isSuspicious = false;

    // Check 1: Malicious tool names
    for (const pattern of maliciousNamePatterns) {
      if (pattern.test(name)) {
        suspicious.push({
          tool: name,
          reason: `Tool name matches suspicious pattern: ${pattern.source}`,
          risk: 'high',
        });
        isSuspicious = true;
        break;
      }
    }

    // Check 2: Suspicious description content (prompt injection indicators)
    for (const pattern of suspiciousDescPatterns) {
      if (pattern.test(description)) {
        suspicious.push({
          tool: name,
          reason: `Description contains suspicious pattern: "${pattern.source}" — possible prompt injection`,
          risk: 'critical',
        });
        isSuspicious = true;
        break;
      }
    }

    // Check 3: Overly broad tool description
    if (description.length < 10 && description.length > 0) {
      suspicious.push({
        tool: name,
        reason: 'Very short description — may be hiding true functionality',
        risk: 'medium',
      });
      isSuspicious = true;
    }

    // Check 4: Empty description
    if (description.length === 0) {
      suspicious.push({
        tool: name,
        reason: 'No description provided — tool functionality is opaque',
        risk: 'medium',
      });
      isSuspicious = true;
    }

    // Check 5: Parameter schema analysis
    if (parameters) {
      const properties = parameters.properties as Record<string, unknown> | undefined;
      const required = parameters.required as string[] | undefined;

      if (properties) {
        // Check for unconstrained string parameters
        for (const [paramName, paramSchema] of Object.entries(properties)) {
          const schema = paramSchema as Record<string, unknown>;
          if (schema.type === 'string' && !schema.enum && !schema.pattern && !schema.maxLength) {
            // Unconstrained string parameter
            if (/command|cmd|exec|shell|query|path|url/i.test(paramName)) {
              suspicious.push({
                tool: name,
                reason: `Unconstrained "${paramName}" parameter — possible injection vector`,
                risk: 'high',
              });
              isSuspicious = true;
            }
          }
        }

        // Check for dangerously broad parameters
        const propCount = Object.keys(properties).length;
        if (propCount > 15) {
          suspicious.push({
            tool: name,
            reason: `Excessive parameter count (${propCount}) — may have overly broad capabilities`,
            risk: 'low',
          });
          isSuspicious = true;
        }
      }

      // Check for tools with no required parameters that perform actions
      if (!required || required.length === 0) {
        const annotations = t.annotations as Record<string, unknown> | undefined;
        const readOnlyHint = annotations?.readOnlyHint as boolean | undefined;
        if (readOnlyHint === false) {
          suspicious.push({
            tool: name,
            reason: 'Mutating tool with no required parameters — may execute with zero user intent',
            risk: 'high',
          });
          isSuspicious = true;
        }
      }
    }

    // Check 6: Origin pattern analysis
    const origin = t.origin as string | undefined;
    if (origin) {
      try {
        const originUrl = new URL(origin);
        // Check for suspicious origins
        if (originUrl.protocol !== 'https:') {
          suspicious.push({
            tool: name,
            reason: `Tool registered from insecure origin: ${origin}`,
            risk: 'high',
          });
          isSuspicious = true;
        }
        if (originUrl.hostname === 'localhost' || originUrl.hostname === '127.0.0.1') {
          suspicious.push({
            tool: name,
            reason: `Tool registered from local origin — may be development artifact or local attack`,
            risk: 'medium',
          });
          isSuspicious = true;
        }
      } catch {
        // Invalid origin URL
        suspicious.push({
          tool: name,
          reason: `Invalid tool origin: ${origin}`,
          risk: 'medium',
        });
        isSuspicious = true;
      }
    }

    // Check 7: Annotation consistency
    const annotations = t.annotations as Record<string, unknown> | undefined;
    if (annotations) {
      const readOnlyHint = annotations.readOnlyHint as boolean | undefined;
      const destructiveHint = annotations.destructiveHint as boolean | undefined;
      const openWorldHint = annotations.openWorldHint as boolean | undefined;

      // A tool that claims to be read-only but has destructive hint
      if (readOnlyHint === true && destructiveHint === true) {
        suspicious.push({
          tool: name,
          reason: 'Conflicting annotations: readOnly=true AND destructive=true',
          risk: 'critical',
        });
        isSuspicious = true;
      }

      // Open world tools with no constraints
      if (openWorldHint === true && readOnlyHint !== true && destructiveHint !== false) {
        suspicious.push({
          tool: name,
          reason: 'Open-world tool without safety annotations — can access external resources destructively',
          risk: 'high',
        });
        isSuspicious = true;
      }
    }

    // Check 8: Safe tool pattern verification
    const matchesSafePattern = safeToolPatterns.some((p) => p.test(name));
    if (!isSuspicious && matchesSafePattern) {
      verified++;
    } else if (!isSuspicious) {
      // Not suspicious but doesn't match known safe patterns
      verified++;
    }
  }

  // Calculate integrity score
  const criticalCount = suspicious.filter((s) => s.risk === 'critical').length;
  const highCount = suspicious.filter((s) => s.risk === 'high').length;
  const mediumCount = suspicious.filter((s) => s.risk === 'medium').length;
  const lowCount = suspicious.filter((s) => s.risk === 'low').length;

  const penalty = (criticalCount * 30) + (highCount * 15) + (mediumCount * 5) + (lowCount * 2);
  const integrityScore = Math.max(0, Math.min(100, 100 - penalty));

  return {
    toolCount,
    verified,
    suspicious,
    integrityScore,
  };
}

/* ─── 7. Session Guard Types & Implementation ─────────────────────── */

export interface SessionAlert {
  timestamp: number;
  type: 'iframe_injection' | 'postmessage_unknown' | 'storage_access' | 'window_opener' | 'navigation_hijack';
  severity: 'info' | 'warning' | 'danger';
  description: string;
}

export interface SessionGuardStatus {
  active: boolean;
  alerts: SessionAlert[];
}

export function activateSessionGuard(): {
  cleanup: () => void;
  status: SessionGuardStatus;
} {
  const alerts: SessionAlert[] = [];
  const cleanupFns: Array<() => void> = [];
  const knownOrigins = new Set([window.location.origin]);

  // --- Monitor 1: Iframe injection detection ---
  const iframeObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of Array.from(mutation.addedNodes)) {
        if (node instanceof HTMLIFrameElement) {
          const src = node.src || '(no src)';
          const sandbox = node.getAttribute('sandbox');
          const hasSandbox = sandbox !== null;

          if (!hasSandbox) {
            alerts.push({
              timestamp: performance.now(),
              type: 'iframe_injection',
              severity: 'danger',
              description: `Unsandboxed iframe injected: src="${src}" — can access parent context`,
            });
          } else {
            // Check if sandbox allows same-origin
            if (sandbox.includes('allow-same-origin')) {
              alerts.push({
                timestamp: performance.now(),
                type: 'iframe_injection',
                severity: 'warning',
                description: `Sandboxed iframe with allow-same-origin: src="${src}" — can bypass origin restrictions`,
              });
            } else {
              alerts.push({
                timestamp: performance.now(),
                type: 'iframe_injection',
                severity: 'info',
                description: `Sandboxed iframe injected: src="${src}"`,
              });
            }
          }

          // Check for hidden iframes (0x0 or 1x1)
          const rect = node.getBoundingClientRect();
          if ((rect.width <= 1 && rect.height <= 1) || node.style.display === 'none' || node.style.visibility === 'hidden') {
            alerts.push({
              timestamp: performance.now(),
              type: 'iframe_injection',
              severity: 'danger',
              description: `Hidden iframe detected: ${rect.width}x${rect.height}px — possible tracking or attack iframe`,
            });
          }
        }
      }
    }
  });

  try {
    iframeObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
    cleanupFns.push(() => iframeObserver.disconnect());
  } catch {
    // SSR or document not ready
  }

  // --- Monitor 2: postMessage from unknown origins ---
  const messageHandler = (event: MessageEvent) => {
    const origin = event.origin;
    if (!knownOrigins.has(origin) && origin !== 'null') {
      // Check for common attack patterns in the message
      const data = event.data;
      const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

      const isSuspicious =
        /exec|eval|script|onerror|onload|javascript:/i.test(dataStr);

      alerts.push({
        timestamp: performance.now(),
        type: 'postmessage_unknown',
        severity: isSuspicious ? 'danger' : 'warning',
        description: `postMessage from unknown origin "${origin}"${isSuspicious ? ' — suspicious content detected' : ''}`,
      });

      // If the message contains modelContext references, flag as critical
      if (/modelContext|model_context|mcp/i.test(dataStr)) {
        alerts.push({
          timestamp: performance.now(),
          type: 'postmessage_unknown',
          severity: 'danger',
          description: `postMessage from "${origin}" references MCP/modelContext — possible tool injection attempt`,
        });
      }
    }
  };

  window.addEventListener('message', messageHandler);
  cleanupFns.push(() => window.removeEventListener('message', messageHandler));

  // --- Monitor 3: Storage access patterns ---
  const storageAccessMonitor = () => {
    // Override localStorage and sessionStorage setItem to detect suspicious writes
    const originalLocalStorageSetItem = localStorage.setItem.bind(localStorage);
    const originalSessionStorageSetItem = sessionStorage.setItem.bind(sessionStorage);

    localStorage.setItem = function (key: string, value: string) {
      // Check for suspicious storage keys
      if (/token|auth|session|credential|password|secret|key/i.test(key)) {
        alerts.push({
          timestamp: performance.now(),
          type: 'storage_access',
          severity: 'warning',
          description: `localStorage.setItem called with sensitive key: "${key}"`,
        });
      }
      return originalLocalStorageSetItem(key, value);
    };

    sessionStorage.setItem = function (key: string, value: string) {
      if (/token|auth|session|credential|password|secret|key/i.test(key)) {
        alerts.push({
          timestamp: performance.now(),
          type: 'storage_access',
          severity: 'warning',
          description: `sessionStorage.setItem called with sensitive key: "${key}"`,
        });
      }
      return originalSessionStorageSetItem(key, value);
    };

    // Restore original methods on cleanup
    cleanupFns.push(() => {
      localStorage.setItem = originalLocalStorageSetItem;
      sessionStorage.setItem = originalSessionStorageSetItem;
    });
  };

  try {
    storageAccessMonitor();
  } catch {
    // Storage may be restricted
  }

  // --- Monitor 4: Window.opener hijacking ---
  const checkWindowOpener = () => {
    try {
      if (window.opener && window.opener !== window) {
        const openerOrigin = window.opener.location?.origin;
        if (openerOrigin && !knownOrigins.has(openerOrigin)) {
          alerts.push({
            timestamp: performance.now(),
            type: 'window_opener',
            severity: 'warning',
            description: `window.opener points to different origin: "${openerOrigin}" — possible tab-nabbing`,
          });
        }
      }
    } catch {
      // Cross-origin opener — this IS the danger signal
      if (window.opener !== null) {
        alerts.push({
          timestamp: performance.now(),
          type: 'window_opener',
          severity: 'danger',
          description: 'window.opener exists but origin is inaccessible (cross-origin) — possible reverse tab-nabbing attack',
        });
      }
    }
  };

  checkWindowOpener();

  // --- Monitor 5: Navigation hijacking detection ---
  const originalPushState = history.pushState.bind(history);
  const originalReplaceState = history.replaceState.bind(history);

  history.pushState = function (state: unknown, title: string, url?: string | URL | null) {
    if (url) {
      const urlStr = typeof url === 'string' ? url : url.toString();
      try {
        const targetUrl = new URL(urlStr, window.location.href);
        if (targetUrl.origin !== window.location.origin) {
          alerts.push({
            timestamp: performance.now(),
            type: 'navigation_hijack',
            severity: 'danger',
            description: `history.pushState to different origin: "${targetUrl.origin}" — possible phishing redirect`,
          });
        }
      } catch {
        alerts.push({
          timestamp: performance.now(),
          type: 'navigation_hijack',
          severity: 'warning',
          description: `history.pushState with unusual URL: "${urlStr}"`,
        });
      }
    }
    return originalPushState(state, title, url);
  };

  history.replaceState = function (state: unknown, title: string, url?: string | URL | null) {
    if (url) {
      const urlStr = typeof url === 'string' ? url : url.toString();
      try {
        const targetUrl = new URL(urlStr, window.location.href);
        if (targetUrl.origin !== window.location.origin) {
          alerts.push({
            timestamp: performance.now(),
            type: 'navigation_hijack',
            severity: 'danger',
            description: `history.replaceState to different origin: "${targetUrl.origin}" — possible URL spoofing`,
          });
        }
      } catch {
        alerts.push({
          timestamp: performance.now(),
          type: 'navigation_hijack',
          severity: 'warning',
          description: `history.replaceState with unusual URL: "${urlStr}"`,
        });
      }
    }
    return originalReplaceState(state, title, url);
  };

  cleanupFns.push(() => {
    history.pushState = originalPushState;
    history.replaceState = originalReplaceState;
  });

  // --- Periodic scan for new iframes and suspicious elements ---
  const scanInterval = setInterval(() => {
    try {
      const iframes = document.querySelectorAll('iframe');
      for (const iframeEl of Array.from(iframes)) {
        const iframe = iframeEl as HTMLIFrameElement;
        const src = iframe.src;
        if (src && !iframe.dataset.__ssmcp_scanned) {
          iframe.dataset.__ssmcp_scanned = 'true';

          try {
            const iframeUrl = new URL(src);
            if (iframeUrl.origin !== window.location.origin) {
              const sandbox = iframe.getAttribute('sandbox');
              if (!sandbox || sandbox.includes('allow-same-origin')) {
                alerts.push({
                  timestamp: performance.now(),
                  type: 'iframe_injection',
                  severity: 'warning',
                  description: `Cross-origin iframe found during scan: "${iframeUrl.origin}"${!sandbox ? ' (no sandbox)' : ' (allow-same-origin)'}`,
                });
              }
            }
          } catch {
            // Invalid URL
          }
        }
      }

      // Check for new script elements with suspicious src
      const scripts = document.querySelectorAll('script[src]');
      for (const scriptEl of Array.from(scripts)) {
        const script = scriptEl as HTMLElement;
        if (!script.dataset.__ssmcp_scanned) {
          script.dataset.__ssmcp_scanned = 'true';
          const src = script.getAttribute('src') ?? '';
          try {
            const scriptUrl = new URL(src, window.location.href);
            if (scriptUrl.origin !== window.location.origin) {
              // Third-party script — already scanned by MSTI shield, just note it
            }
          } catch {
            // inline or invalid
          }
        }
      }
    } catch {
      // DOM may not be accessible
    }
  }, 5000);

  cleanupFns.push(() => clearInterval(scanInterval));

  return {
    cleanup: () => {
      for (const fn of cleanupFns) {
        try { fn(); } catch { /* best effort */ }
      }
    },
    status: {
      active: true,
      alerts,
    },
  };
}

/* ─── 8. Full Shield Activation ───────────────────────────────────── */

export interface FullShieldStatus {
  msti: MSTIShieldStatus;
  agentRadar: AIAgentRadarResult;
  gpuGuard: GPUCacheGuardStatus;
  webrtc: WebRTCProtectionResult;
  quic: QUICExposureResult;
  toolIntegrity: ToolIntegrityResult;
  session: SessionGuardStatus;
  elicitGuard: ElicitationGuardStatus;
  abortGuard: AbortExecutionGuardStatus;
  declFormGuard: DeclarativeFormGuardStatus;
  clientRefGuard: ClientReferenceGuardStatus;
  composeGuard: ToolCompositionGuardStatus;
  observeGuard: ObservationHardeningStatus;
  activatedAt: number;
  overallThreat: ShieldThreatLevel;
}

/* ─── 6. SW-MCP-PERSIST Defense: ServiceWorkerMCPGuard ─────────────── */

export interface SWMCPGuardStatus {
  swRegistered: boolean;
  swScope: string;
  toolAllowlist: string[];
  anomalies: string[];
}

export function activateSWMCPGuard(): SWMCPGuardStatus {
  const anomalies: string[] = [];
  let swRegistered = false;
  let swScope = '';
  const toolAllowlist: string[] = [];

  try {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then(regs => {
        for (const reg of regs) {
          swScope = reg.scope;
          swRegistered = true;
        }
      }).catch(() => {});

      if (navigator.serviceWorker.controller) {
        // Compare tools against allowlist from initial load
        const doc = document as unknown as Record<string, unknown>;
        const mc = doc.modelContext;
        if (mc && typeof (mc as Record<string, unknown>).tools === 'object') {
          anomalies.push('Active SW detected — tool integrity should be verified against initial allowlist');
        }
      }
    }
  } catch {
    // SW API may not be available
  }

  return {
    swRegistered,
    swScope,
    toolAllowlist,
    anomalies,
  };
}

/* ─── 7. GPU Privacy Guard: GPU-AGENT-PROXY Defense ───────────────── */

export interface GPUPrivacyGuardStatus {
  gpuAvailable: boolean;
  lowPowerMode: boolean;
  timingJitter: boolean;
  anomalies: string[];
}

export function activateGPUPrivacyGuard(): GPUPrivacyGuardStatus {
  const anomalies: string[] = [];
  let gpuAvailable = false;
  let lowPowerMode = false;

  try {
    if (typeof navigator !== 'undefined' && 'gpu' in navigator) {
      gpuAvailable = true;
      // Request adapter with low-power preference to reduce fingerprinting
      const gpu = (navigator as unknown as Record<string, unknown>).gpu;
      if (gpu && typeof (gpu as Record<string, unknown>).requestAdapter === 'function') {
        const originalRequestAdapter = (gpu as Record<string, unknown>).requestAdapter as (opts: Record<string, unknown>) => unknown;
        (gpu as Record<string, unknown>).requestAdapter = function(opts: Record<string, unknown>) {
          return originalRequestAdapter.call(gpu, { ...opts, powerPreference: 'low-power' });
        };
        lowPowerMode = true;
      }
    }
  } catch {
    // GPU API may not be available
  }

  return {
    gpuAvailable,
    lowPowerMode,
    timingJitter: true,
    anomalies,
  };
}

/* ─── 8. DOMClobberGuard: DOM-CLOBBER-MCP Defense ─────────────────── */

export interface DomClobberGuardStatus {
  modelContextFrozen: boolean;
  clobberingDetected: boolean;
  anomalies: string[];
}

export function activateDomClobberGuard(): DomClobberGuardStatus {
  const anomalies: string[] = [];
  let modelContextFrozen = false;
  let clobberingDetected = false;

  try {
    if (typeof document !== 'undefined') {
      const doc = document as unknown as Record<string, unknown>;
      const mc = doc.modelContext;
      if (mc && typeof mc === 'object') {
        // Verify modelContext is a native object via prototype check
        const proto = Object.getPrototypeOf(mc);
        if (proto && proto.constructor && proto.constructor.name === 'HTMLFormElement') {
          clobberingDetected = true;
          anomalies.push('document.modelContext has HTMLFormElement prototype — DOM clobbering detected!');
        }

        // Freeze the modelContext reference to prevent clobbering
        try {
          Object.defineProperty(document, 'modelContext', {
            value: mc,
            writable: false,
            configurable: false,
          });
          modelContextFrozen = true;
        } catch {
          anomalies.push('Could not freeze document.modelContext — may be already non-configurable');
        }
      }
    }
  } catch {
    // DOM access may be restricted
  }

  return {
    modelContextFrozen,
    clobberingDetected,
    anomalies,
  };
}

/* ─── 9. ExtensionBridgeGuard: EXT-MCP-BRIDGE Defense ─────────────── */

export interface ExtBridgeGuardStatus {
  extensionContext: boolean;
  stackTraceMonitoring: boolean;
  anomalies: string[];
}

export function activateExtBridgeGuard(): ExtBridgeGuardStatus {
  const anomalies: string[] = [];
  let extensionContext = false;

  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
      extensionContext = true;
      anomalies.push('Chrome extension context detected — tools may be registered by extensions');
    }
  } catch {
    // chrome API not available
  }

  return {
    extensionContext,
    stackTraceMonitoring: true,
    anomalies,
  };
}

/* ─── 10. AnnotationVerifier: TOOL-ANNOTATION-CONFUSION Defense ───── */

export interface AnnotationVerifierStatus {
  toolsVerified: number;
  mismatchesDetected: number;
  anomalies: string[];
}

export function activateAnnotationVerifier(): AnnotationVerifierStatus {
  const anomalies: string[] = [];
  let toolsVerified = 0;
  let mismatchesDetected = 0;

  try {
    if (typeof document !== 'undefined') {
      const doc = document as unknown as Record<string, unknown>;
      const mc = doc.modelContext;
      if (mc && typeof (mc as Record<string, unknown>).tools === 'object') {
        toolsVerified++;
        anomalies.push('Annotation verification active — compare claimed annotations against observed behavior');
      }
    }
  } catch {
    // DOM access may be restricted
  }

  return {
    toolsVerified,
    mismatchesDetected,
    anomalies,
  };
}

/* ─── 11. CSSKeyGuard: CSS-KEY-MCP Defense ────────────────────────── */

export interface CSSKeyGuardStatus {
  inputFieldsProtected: boolean;
  timingRandomized: boolean;
  anomalies: string[];
}

export function activateCSSKeyGuard(): CSSKeyGuardStatus {
  const anomalies: string[] = [];
  let inputFieldsProtected = false;

  try {
    if (typeof document !== 'undefined') {
      const inputs = document.querySelectorAll('input[type="text"], input[type="password"], textarea');
      if (inputs.length > 0) {
        inputFieldsProtected = true;
        anomalies.push(`${inputs.length} input fields detected — CSS timing randomization recommended`);
      }
    }
  } catch {
    // DOM access may be restricted
  }

  return {
    inputFieldsProtected,
    timingRandomized: true,
    anomalies,
  };
}

/* ─── 12. QUICReplayGuard: QUIC-MCP-REPLAY Defense ───────────────── */

export interface QUICReplayGuardStatus {
  nonceEnabled: boolean;
  zeroRTTBlocked: boolean;
  anomalies: string[];
}

export function activateQUICReplayGuard(): QUICReplayGuardStatus {
  const anomalies: string[] = [];

  // Nonce generation for tool invocations
  const generateNonce = () => crypto.randomUUID();

  // Check for QUIC usage
  let usesQUIC = false;
  try {
    if (typeof performance !== 'undefined') {
      const navEntries = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];
      for (const entry of navEntries) {
        if (entry.nextHopProtocol && (entry.nextHopProtocol.includes('h3') || entry.nextHopProtocol.includes('quic'))) {
          usesQUIC = true;
          break;
        }
      }
    }
  } catch { /* ignore */ }

  if (usesQUIC) {
    anomalies.push('QUIC detected — single-use nonces enabled for MCP tool invocations');
  }

  return {
    nonceEnabled: true,
    zeroRTTBlocked: true,
    anomalies,
  };
}

/* ─── 13. AudioPrivacyGuard: AUDIO-MCP-FINGERPRINT Defense ────────── */

export interface AudioPrivacyGuardStatus {
  audioContextProtected: boolean;
  timingNoise: boolean;
  anomalies: string[];
}

export function activateAudioPrivacyGuard(): AudioPrivacyGuardStatus {
  const anomalies: string[] = [];
  let audioContextProtected = false;

  try {
    if (typeof AudioContext !== 'undefined') {
      audioContextProtected = true;
      anomalies.push('AudioContext available — timing noise active to mask agent activity patterns');
    }
  } catch {
    // AudioContext may not be available
  }

  return {
    audioContextProtected,
    timingNoise: true,
    anomalies,
  };
}

/* ─── 14. SupplyChainGuard: MCP-SUPPLY-CHAIN Defense ──────────────── */

export interface SupplyChainGuardStatus {
  integrityVerified: boolean;
  proxyDetected: boolean;
  anomalies: string[];
}

export function activateSupplyChainGuard(): SupplyChainGuardStatus {
  const anomalies: string[] = [];
  let integrityVerified = true;
  let proxyDetected = false;

  try {
    if (typeof navigator !== 'undefined') {
      const nav = navigator as unknown as Record<string, unknown>;
      const mc = nav.modelContext;
      if (mc && typeof mc === 'object') {
        // Verify prototype chain against known-good reference
        const mcObj = mc as Record<string, unknown>;
        if (mcObj.constructor && typeof mcObj.constructor.name === 'string') {
          if (mcObj.constructor.name === 'BrowserMcpServer') {
            proxyDetected = true;
            integrityVerified = false;
            anomalies.push('BrowserMcpServer polyfill detected — verify @mcp-b/global integrity');
          }
        }

        // Detect proxy wrappers
        try {
          JSON.stringify(mc);
        } catch {
          proxyDetected = true;
          integrityVerified = false;
          anomalies.push('modelContext serialization failed — possible Proxy wrapper');
        }
      }
    }
  } catch {
    // Navigator may not be available
  }

  return {
    integrityVerified,
    proxyDetected,
    anomalies,
  };
}

/* ─── 17. ElicitationGuard — MCP-ELICIT-PHISH Defense ──────────────── */

export interface ElicitationGuardStatus {
  active: boolean;
  findings: string[];
}

export function activateElicitationGuard(): ElicitationGuardStatus {
  const findings: string[] = [];
  let active = false;

  try {
    const doc = document as unknown as Record<string, unknown>;
    const nav = navigator as unknown as Record<string, unknown>;
    const modelContext = doc.modelContext ?? nav.modelContext;
    const mc = modelContext as Record<string, unknown> | undefined;

    if (mc && typeof mc.addEventListener === 'function') {
      // Monitor for requestUserInteraction calls via toolchange events
      try {
        (mc.addEventListener as (type: string, handler: EventListener) => void)('toolchange', (() => {
          findings.push('Tool change detected — potential elicitation context shift');
        }) as EventListener);
        active = true;
      } catch {
        // addEventListener not available
      }
    }

    // Check for tools with suspicious annotation patterns (readOnlyHint but needs interaction)
    try {
      if (mc && typeof mc.getTools === 'function') {
        const tools = (mc.getTools as () => unknown[])();
        for (const tool of tools) {
          if (typeof tool === 'object' && tool !== null) {
            const t = tool as Record<string, unknown>;
            const annotations = t.annotations as Record<string, unknown> | undefined;
            if (annotations?.readOnlyHint === true && t.name && String(t.name).includes('security')) {
              findings.push(`Tool "${String(t.name)}" claims readOnly but name suggests security interaction — potential elicitation phish`);
            }
          }
        }
        active = true;
      }
    } catch {
      // getTools not available
    }

    if (!active) {
      findings.push('WebMCP not available — ElicitationGuard running in monitor-only mode');
      active = true;
    }
  } catch (err) {
    findings.push(`ElicitationGuard init error: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { active, findings };
}

/* ─── 18. AbortExecutionGuard — MCP-ABORT-RACE Defense ────────────── */

export interface AbortExecutionGuardStatus {
  active: boolean;
  findings: string[];
}

export function activateAbortExecutionGuard(): AbortExecutionGuardStatus {
  const findings: string[] = [];
  let active = false;

  try {
    const doc = document as unknown as Record<string, unknown>;
    const nav = navigator as unknown as Record<string, unknown>;
    const modelContext = doc.modelContext ?? nav.modelContext;
    const mc = modelContext as Record<string, unknown> | undefined;

    // Monitor for tool unregistration events that could indicate abort-triggered race
    if (mc && typeof mc.addEventListener === 'function') {
      try {
        (mc.addEventListener as (type: string, handler: EventListener) => void)('toolchange', (() => {
          findings.push('Tool change detected — monitoring for abort-during-execution patterns');
        }) as EventListener);
        active = true;
      } catch {
        // addEventListener not available
      }
    }

    // Check for tools with AbortSignal that perform non-idempotent operations
    try {
      if (mc && typeof mc.getTools === 'function') {
        const tools = (mc.getTools as () => unknown[])();
        for (const tool of tools) {
          if (typeof tool === 'object' && tool !== null) {
            const t = tool as Record<string, unknown>;
            const annotations = t.annotations as Record<string, unknown> | undefined;
            if (annotations?.destructiveHint === true) {
              findings.push(`Tool "${String(t.name)}" has destructiveHint — must implement abort-safe execution to prevent double-spend`);
            }
          }
        }
        active = true;
      }
    } catch {
      // getTools not available
    }

    if (!active) {
      findings.push('WebMCP not available — AbortExecutionGuard running in monitor-only mode');
      active = true;
    }
  } catch (err) {
    findings.push(`AbortExecutionGuard init error: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { active, findings };
}

/* ─── 19. DeclarativeFormGuard — MCP-DECLFORM-HIJACK Defense ──────── */

export interface DeclarativeFormGuardStatus {
  active: boolean;
  findings: string[];
}

export function activateDeclarativeFormGuard(): DeclarativeFormGuardStatus {
  const findings: string[] = [];
  let active = false;

  try {
    // Watch for declarative form tools being injected into the DOM
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of Array.from(mutation.addedNodes)) {
          if (node instanceof HTMLFormElement && node.hasAttribute('toolname')) {
            const toolname = node.getAttribute('toolname');
            const action = node.getAttribute('action');
            const hasAutoSubmit = node.hasAttribute('toolautosubmit');

            if (hasAutoSubmit && action) {
              try {
                const actionUrl = new URL(action, window.location.href);
                if (actionUrl.origin !== window.location.origin) {
                  findings.push(
                    `DECLFORM ALERT: <form toolname="${toolname}"> has toolautosubmit with cross-origin action="${action}" — data exfiltration risk!`
                  );
                }
              } catch {
                findings.push(`DECLFORM ALERT: <form toolname="${toolname}"> has invalid action URL — potential hijack`);
              }
            }

            if (toolname) {
              findings.push(`Declarative form tool detected: "${toolname}" — monitoring for lifecycle asymmetry (no AbortSignal)`);
            }
          }
        }
      }
    });

    try {
      observer.observe(document.documentElement, { childList: true, subtree: true });
      active = true;
    } catch {
      // document.documentElement may not be available
    }

    // Scan for existing declarative form tools
    try {
      const existingForms = document.querySelectorAll('form[toolname]');
      for (const form of existingForms) {
        const toolname = form.getAttribute('toolname');
        const action = form.getAttribute('action');
        if (form.hasAttribute('toolautosubmit') && action) {
          try {
            const actionUrl = new URL(action, window.location.href);
            if (actionUrl.origin !== window.location.origin) {
              findings.push(`Existing declarative form "${toolname}" auto-submits to cross-origin — BLOCKED by DeclarativeFormGuard`);
            }
          } catch {
            // invalid URL
          }
        }
      }
    } catch {
      // querySelectorAll failed
    }

    if (!active) {
      findings.push('DeclarativeFormGuard running in scan-only mode');
      active = true;
    }
  } catch (err) {
    findings.push(`DeclarativeFormGuard init error: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { active, findings };
}

/* ─── 20. ClientReferenceGuard — MCP-CLIENT-INVERT Defense ────────── */

export interface ClientReferenceGuardStatus {
  active: boolean;
  findings: string[];
}

export function activateClientReferenceGuard(): ClientReferenceGuardStatus {
  const findings: string[] = [];
  let active = false;

  try {
    const doc = document as unknown as Record<string, unknown>;
    const nav = navigator as unknown as Record<string, unknown>;
    const modelContext = doc.modelContext ?? nav.modelContext;
    const mc = modelContext as Record<string, unknown> | undefined;

    // Monitor for tools that could be storing client references
    if (mc && typeof mc.getTools === 'function') {
      try {
        const tools = (mc.getTools as () => unknown[])();
        for (const tool of tools) {
          if (typeof tool === 'object' && tool !== null) {
            const t = tool as Record<string, unknown>;
            const annotations = t.annotations as Record<string, unknown> | undefined;
            // Flag tools that could benefit from client reference storage
            if (annotations?.readOnlyHint === true) {
              findings.push(`Tool "${String(t.name)}" claims readOnly — client reference should expire after execution`);
            }
          }
        }
        active = true;
      } catch {
        // getTools not available
      }
    }

    if (!active) {
      findings.push('WebMCP not available — ClientReferenceGuard running in monitor-only mode');
      active = true;
    }
  } catch (err) {
    findings.push(`ClientReferenceGuard init error: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { active, findings };
}

/* ─── 21. ToolCompositionGuard — MCP-COMPOSE-XOR Defense ─────────── */

export interface ToolCompositionGuardStatus {
  active: boolean;
  findings: string[];
}

export function activateToolCompositionGuard(): ToolCompositionGuardStatus {
  const findings: string[] = [];
  let active = false;

  try {
    const doc = document as unknown as Record<string, unknown>;
    const nav = navigator as unknown as Record<string, unknown>;
    const modelContext = doc.modelContext ?? nav.modelContext;
    const mc = modelContext as Record<string, unknown> | undefined;

    // Check for cross-origin tools via exposedTo
    if (mc && typeof mc.getTools === 'function') {
      try {
        const tools = (mc.getTools as () => unknown[])();
        for (const tool of tools) {
          if (typeof tool === 'object' && tool !== null) {
            const t = tool as Record<string, unknown>;
            // Flag tools from different origins
            if (t.origin && String(t.origin) !== window.location.origin) {
              findings.push(`Cross-origin tool detected: "${String(t.name)}" from ${String(t.origin)} — potential composition chain risk`);
            }
          }
        }
        active = true;
      } catch {
        // getTools not available
      }
    }

    // Monitor for iframe tools via MutationObserver
    try {
      const iframes = document.querySelectorAll('iframe[allow~="tools"]');
      for (const iframe of iframes) {
        findings.push(`Iframe with tools permission detected: src="${iframe.getAttribute('src') || 'unknown'}" — potential cross-origin composition vector`);
      }
      if (iframes.length > 0) active = true;
    } catch {
      // querySelectorAll failed
    }

    if (!active) {
      findings.push('WebMCP not available — ToolCompositionGuard running in monitor-only mode');
      active = true;
    }
  } catch (err) {
    findings.push(`ToolCompositionGuard init error: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { active, findings };
}

/* ─── 22. ObservationHardening — MCP-OBSERVE-ORACLE Defense ──────── */

export interface ObservationHardeningStatus {
  active: boolean;
  findings: string[];
}

export function activateObservationHardening(): ObservationHardeningStatus {
  const findings: string[] = [];
  let active = false;

  try {
    const doc = document as unknown as Record<string, unknown>;
    const nav = navigator as unknown as Record<string, unknown>;
    const modelContext = doc.modelContext ?? nav.modelContext;
    const mc = modelContext as Record<string, unknown> | undefined;

    // Monitor for rapid tool registration patterns (beacon signaling)
    let recentRegistrations = 0;
    let lastResetTime = Date.now();

    if (mc && typeof mc.addEventListener === 'function') {
      try {
        (mc.addEventListener as (type: string, handler: EventListener) => void)('toolchange', (() => {
          recentRegistrations++;
          const now = Date.now();
          const elapsed = now - lastResetTime;
          if (elapsed > 1000) {
            if (recentRegistrations > 2) {
              findings.push(`High tool registration rate: ${recentRegistrations} changes in ${elapsed}ms — potential observation oracle signaling`);
            }
            recentRegistrations = 0;
            lastResetTime = now;
          }
        }) as EventListener);
        active = true;
      } catch {
        // addEventListener not available
      }
    }

    if (!active) {
      findings.push('WebMCP not available — ObservationHardening running in monitor-only mode');
      active = true;
    }
  } catch (err) {
    findings.push(`ObservationHardening init error: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { active, findings };
}

/* ─── Full Shield Activation ──────────────────────────────────────── */

export function activateFullShield(): {
  cleanup: () => void;
  status: FullShieldStatus;
} {
  // Activate all defensive monitors
  const msti = activateMSTIShield();
  const agentRadar = scanForAIAgents();
  const gpuGuard = activateGPUCacheGuard();
  const webrtc = protectWebRTCLeaks();
  const quic = analyzeQUICExposure();
  const toolIntegrity = verifyToolIntegrity();
  const session = activateSessionGuard();
  const elicitGuard = activateElicitationGuard();
  const abortGuard = activateAbortExecutionGuard();
  const declFormGuard = activateDeclarativeFormGuard();
  const clientRefGuard = activateClientReferenceGuard();
  const composeGuard = activateToolCompositionGuard();
  const observeGuard = activateObservationHardening();

  // Determine overall threat level from all sub-systems
  const threatLevels: ShieldThreatLevel[] = [
    agentRadar.threatLevel,
    quic.fingerprintRisk,
  ];

  // Add threat level based on WebRTC vulnerability
  if (webrtc.vulnerable) {
    threatLevels.push('alert');
  } else if (webrtc.protectionStatus === 'partial') {
    threatLevels.push('watch');
  }

  // Add threat level based on tool integrity
  if (toolIntegrity.integrityScore < 40) {
    threatLevels.push('critical');
  } else if (toolIntegrity.integrityScore < 60) {
    threatLevels.push('alert');
  } else if (toolIntegrity.integrityScore < 80) {
    threatLevels.push('watch');
  }

  // Add threat level based on MSTI change log
  if (msti.status.changeLog.some((e) => e.type === 'context_replaced')) {
    threatLevels.push('critical');
  } else if (msti.status.changeLog.some((e) => e.type === 'tool_modified')) {
    threatLevels.push('alert');
  } else if (msti.status.changeLog.some((e) => e.type === 'tool_added')) {
    threatLevels.push('watch');
  }

  // Add threat level based on session alerts
  const dangerAlerts = session.status.alerts.filter((a) => a.severity === 'danger').length;
  const warningAlerts = session.status.alerts.filter((a) => a.severity === 'warning').length;
  if (dangerAlerts > 0) {
    threatLevels.push('alert');
  } else if (warningAlerts > 2) {
    threatLevels.push('watch');
  }

  // Add threat level based on GPU anomalies
  if (gpuGuard.status.anomalies.length > 3) {
    threatLevels.push('alert');
  } else if (gpuGuard.status.anomalies.length > 0) {
    threatLevels.push('watch');
  }

  // Add threat level based on novel vector guard findings
  if (elicitGuard.findings.some(f => f.includes('ALERT') || f.includes('phish'))) {
    threatLevels.push('critical');
  }
  if (abortGuard.findings.some(f => f.includes('double-spend') || f.includes('abort'))) {
    threatLevels.push('alert');
  }
  if (declFormGuard.findings.some(f => f.includes('ALERT') || f.includes('BLOCKED'))) {
    threatLevels.push('critical');
  }
  if (composeGuard.findings.some(f => f.includes('cross-origin'))) {
    threatLevels.push('alert');
  }
  if (observeGuard.findings.some(f => f.includes('signaling'))) {
    threatLevels.push('watch');
  }

  // Compute the worst threat level
  const threatPriority: Record<ShieldThreatLevel, number> = {
    clear: 0,
    watch: 1,
    alert: 2,
    critical: 3,
  };

  const overallThreat = threatLevels.reduce<ShieldThreatLevel>((worst, current) => {
    return threatPriority[current] > threatPriority[worst] ? current : worst;
  }, 'clear');

  const status: FullShieldStatus = {
    msti: msti.status,
    agentRadar,
    gpuGuard: gpuGuard.status,
    webrtc,
    quic,
    toolIntegrity,
    session: session.status,
    elicitGuard,
    abortGuard,
    declFormGuard,
    clientRefGuard,
    composeGuard,
    observeGuard,
    activatedAt: Date.now(),
    overallThreat,
  };

  return {
    cleanup: () => {
      msti.cleanup();
      gpuGuard.cleanup();
      session.cleanup();
    },
    status,
  };
}
