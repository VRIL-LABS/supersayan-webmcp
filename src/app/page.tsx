'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Scan,
  Eye,
  Fingerprint,
  Globe,
  AlertTriangle,
  Bug,
  Terminal,
  Activity,
  Zap,
  Lock,
  Server,
  Wifi,
  Cpu,
  Monitor,
  Code2,
  ArrowRight,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Info,
  MapPin,
  Building2,
  Cloud,
  Radio,
  Search,
  FileWarning,
  ExternalLink,
  Github,
  BookOpen,
  Scale,
  MousePointer2,
  Framer,
  GitBranch,
  Webhook,
  Database,
  KeyRound,
  Network,
  Timer,
  Gauge,
  ScanLine,
  Braces,
  Layers,
  Chrome,
  UserCheck,
  Bot,
  CircleDot,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  type DetectionResult,
  type DetectionSignal,
  type ThreatLevel,
  type BrowserFingerprint,
  type WebMCPAnalysis,
  type AttributionReport,
  type RiskFactor,
  type MCPCVE,
  runFullDetection,
  startBehavioralTracking,
  getThreatColor,
  getThreatLabel,
  MCP_CVE_DATABASE,
  generateAttributionReport,
} from '@/lib/supersayan';

/* ────────────────────────────────────────────────────────────────── */
/*  Animation variants                                               */
/* ────────────────────────────────────────────────────────────────── */

const fadeInUp = {
  hidden: { opacity: 0, y: 24 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.5, ease: 'easeOut' },
  }),
};

const staggerContainer = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.06 } },
};

const fadeInScale = {
  hidden: { opacity: 0, scale: 0.95 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.4, ease: 'easeOut' } },
};

/* ────────────────────────────────────────────────────────────────── */
/*  Helper Components                                                */
/* ────────────────────────────────────────────────────────────────── */

function CategoryBadge({ category }: { category: DetectionSignal['category'] }) {
  const config: Record<string, { color: string; label: string }> = {
    headless: { color: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10', label: 'Headless' },
    automation: { color: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10', label: 'Automation' },
    ai_agent: { color: 'text-sayan-cyan border-sayan-cyan/30 bg-sayan-cyan/10', label: 'AI Agent' },
    webmcp: { color: 'text-sayan-emerald border-sayan-emerald/30 bg-sayan-emerald/10', label: 'WebMCP' },
    covert_channel: { color: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10', label: 'Covert Ch.' },
  };
  const c = config[category] || { color: 'text-text-dim border-border-custom bg-muted', label: category };
  return (
    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${c.color}`}>
      {c.label}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: number }) {
  const color =
    severity >= 9.0
      ? 'text-sayan-red border-sayan-red/30 bg-sayan-red/10'
      : severity >= 7.0
        ? 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10'
        : severity >= 4.0
          ? 'text-yellow-400 border-yellow-400/30 bg-yellow-400/10'
          : 'text-sayan-emerald border-sayan-emerald/30 bg-sayan-emerald/10';
  return (
    <Badge variant="outline" className={`text-xs font-mono px-2 ${color}`}>
      {severity.toFixed(1)}
    </Badge>
  );
}

function SourceTypeBadge({ type }: { type: string }) {
  const config: Record<string, { color: string; icon: React.ReactNode }> = {
    residential: { color: 'text-sayan-emerald border-sayan-emerald/30 bg-sayan-emerald/10', icon: <UserCheck className="h-3 w-3 mr-1" /> },
    datacenter: { color: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10', icon: <Server className="h-3 w-3 mr-1" /> },
    vpn: { color: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10', icon: <ShieldAlert className="h-3 w-3 mr-1" /> },
    tor: { color: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10', icon: <Eye className="h-3 w-3 mr-1" /> },
    proxy: { color: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10', icon: <Network className="h-3 w-3 mr-1" /> },
    unknown: { color: 'text-text-dim border-border-custom bg-muted', icon: <CircleDot className="h-3 w-3 mr-1" /> },
  };
  const c = config[type] || config.unknown;
  return (
    <Badge variant="outline" className={`text-xs px-3 py-1 ${c.color}`}>
      {c.icon}
      {type.toUpperCase()}
    </Badge>
  );
}

function RiskFactorBadge({ severity }: { severity: RiskFactor['severity'] }) {
  const config: Record<string, string> = {
    info: 'text-sayan-emerald border-sayan-emerald/30 bg-sayan-emerald/10',
    low: 'text-green-400 border-green-400/30 bg-green-400/10',
    medium: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10',
    high: 'text-orange-400 border-orange-400/30 bg-orange-400/10',
    critical: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10',
  };
  return (
    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${config[severity] || ''}`}>
      {severity.toUpperCase()}
    </Badge>
  );
}

function ThreatGauge({ score, level }: { score: number; level: ThreatLevel }) {
  const color = getThreatColor(level);
  const circumference = 2 * Math.PI * 45;
  const dashOffset = circumference - (score / 100) * circumference;
  const label = getThreatLabel(level);

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="#1e1e2e" strokeWidth="8" />
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            className="gauge-animate"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold font-mono" style={{ color }}>
            {score}
          </span>
          <span className="text-[10px] text-text-dim uppercase tracking-wider">Threat</span>
        </div>
      </div>
      <div className="text-center">
        <p className="text-sm font-semibold" style={{ color }}>
          {label}
        </p>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  1. HERO SECTION                                                  */
/* ────────────────────────────────────────────────────────────────── */

function HeroSection() {
  return (
    <section className="relative overflow-hidden pt-16 pb-20 md:pt-28 md:pb-32">
      {/* Animated background */}
      <div className="absolute inset-0 grid-bg pointer-events-none" />
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-32 -left-32 w-96 h-96 bg-sayan-emerald/8 rounded-full blur-[120px]" />
        <div className="absolute -bottom-32 -right-32 w-96 h-96 bg-sayan-cyan/6 rounded-full blur-[120px]" />
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-sayan-emerald/4 rounded-full blur-[150px]" />
      </div>

      {/* Matrix columns — each column uses Math.random() so suppressHydrationWarning on each */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-20">
        {Array.from({ length: 8 }).map((_, i) => (
          <div
            key={i}
            className="matrix-column"
            suppressHydrationWarning
            style={{
              left: `${10 + i * 12}%`,
              animationDuration: `${8 + i * 2}s`,
              animationDelay: `${i * 0.5}s`,
            }}
          >
            {Array.from({ length: 20 })
              .map(() => String.fromCharCode(0x30a0 + Math.random() * 96))
              .join(' ')}
          </div>
        ))}
      </div>

      <div className="relative z-10 max-w-5xl mx-auto px-4 text-center">
        <motion.div initial="hidden" animate="visible" variants={staggerContainer}>
          <motion.div variants={fadeInUp} custom={0}>
            <Badge variant="outline" className="mb-6 border-sayan-emerald/30 text-sayan-emerald bg-sayan-emerald/5 px-4 py-1.5 text-sm">
              <Shield className="h-3.5 w-3.5 mr-1.5" />
              2026 Security Research
            </Badge>
          </motion.div>

          <motion.h1
            variants={fadeInUp}
            custom={1}
            className="text-5xl sm:text-6xl md:text-8xl font-bold tracking-tight mb-6 animate-gradient-sayan"
          >
            SuperSayanMCP
          </motion.h1>

          <motion.p
            variants={fadeInUp}
            custom={2}
            className="text-lg md:text-2xl text-text font-medium mb-4"
          >
            Next-Generation WebMCP Security Intelligence Platform
          </motion.p>

          <motion.p
            variants={fadeInUp}
            custom={3}
            className="text-base md:text-lg text-text-dim max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            Detect. Defend. Trace. The complete countermeasure suite for the agentic web.
          </motion.p>

          <motion.div variants={fadeInUp} custom={4} className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button
              size="lg"
              className="bg-sayan-emerald hover:bg-sayan-emerald/90 text-[#050507] px-8 h-12 text-base glow-emerald font-semibold"
              onClick={() => document.getElementById('detection-dashboard')?.scrollIntoView({ behavior: 'smooth' })}
            >
              <Scan className="h-4 w-4 mr-2" />
              Run Live Scan
              <ArrowRight className="h-4 w-4 ml-1" />
            </Button>
            <Button
              size="lg"
              variant="outline"
              className="border-sayan-red/40 text-sayan-red hover:bg-sayan-red/10 hover:border-sayan-red/60 px-8 h-12 text-base"
              onClick={() => document.getElementById('threat-intel')?.scrollIntoView({ behavior: 'smooth' })}
            >
              <AlertTriangle className="h-4 w-4 mr-2" />
              View Threat Intel
              <ArrowRight className="h-4 w-4 ml-1" />
            </Button>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  2. LIVE DETECTION DASHBOARD                                      */
/* ────────────────────────────────────────────────────────────────── */

function DetectionDashboard() {
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const cleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    cleanupRef.current = startBehavioralTracking();
    return () => {
      cleanupRef.current?.();
    };
  }, []);

  const runScan = useCallback(async () => {
    setScanning(true);
    setScanProgress(0);
    setResult(null);

    // Simulate progressive scan
    const steps = [10, 25, 40, 55, 70, 85, 95, 100];
    for (const step of steps) {
      await new Promise((r) => setTimeout(r, 180));
      setScanProgress(step);
    }

    try {
      const detectionResult = runFullDetection();
      setResult(detectionResult);
    } catch (err) {
      console.error('Detection failed:', err);
    } finally {
      setScanning(false);
      setScanProgress(100);
    }
  }, []);

  return (
    <section id="detection-dashboard" className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-emerald/30 text-sayan-emerald bg-sayan-emerald/5 mb-4">
              <ScanLine className="h-3.5 w-3.5 mr-1.5" />
              Live Scanner
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              Detection Dashboard
            </h2>
            <p className="text-text-dim text-lg max-w-xl mx-auto">
              Run a comprehensive security scan of your browser environment
            </p>
          </div>

          {/* Scan Button */}
          <div className="flex flex-col items-center gap-4 mb-10">
            <Button
              size="lg"
              disabled={scanning}
              onClick={runScan}
              className={`bg-sayan-emerald hover:bg-sayan-emerald/90 text-[#050507] px-10 h-14 text-lg font-bold ${scanning ? '' : 'scan-pulse'}`}
            >
              {scanning ? (
                <>
                  <Activity className="h-5 w-5 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Zap className="h-5 w-5 mr-2" />
                  RUN FULL SCAN
                </>
              )}
            </Button>
            {scanning && (
              <div className="w-full max-w-md">
                <Progress value={scanProgress} className="h-2 bg-surface [&>[data-slot=indicator]]:bg-sayan-emerald" />
                <p className="text-xs text-text-dim mt-2 text-center">
                  Analyzing {scanProgress < 30 ? 'headless indicators' : scanProgress < 60 ? 'behavioral signals' : scanProgress < 90 ? 'covert channels' : 'generating report'}...
                </p>
              </div>
            )}
          </div>

          {/* Results */}
          <AnimatePresence mode="wait">
            {result && (
              <motion.div
                key="results"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.5 }}
                className="space-y-8"
              >
                {/* Score + Summary */}
                <div className="grid md:grid-cols-[auto_1fr] gap-8 items-start">
                  <Card className="bg-surface border-border-custom p-6 flex flex-col items-center">
                    <CardTitle className="text-sm text-text-dim mb-4 uppercase tracking-wider">
                      Threat Score
                    </CardTitle>
                    <ThreatGauge score={result.overallScore} level={result.threatLevel} />
                  </Card>

                  <div className="grid sm:grid-cols-2 gap-4">
                    <Card className="bg-surface border-border-custom p-4 card-hover-emerald">
                      <div className="flex items-center gap-2 mb-2">
                        <Fingerprint className="h-4 w-4 text-sayan-cyan" />
                        <span className="text-sm font-semibold text-text">Detection Signals</span>
                      </div>
                      <p className="text-2xl font-bold font-mono text-text">
                        {result.signals.filter((s) => !s.passed).length}
                        <span className="text-sm text-text-dim">/{result.signals.length}</span>
                      </p>
                      <p className="text-xs text-text-dim mt-1">signals triggered</p>
                    </Card>
                    <Card className="bg-surface border-border-custom p-4 card-hover-emerald">
                      <div className="flex items-center gap-2 mb-2">
                        <Shield className="h-4 w-4 text-sayan-emerald" />
                        <span className="text-sm font-semibold text-text">Threat Level</span>
                      </div>
                      <p className="text-2xl font-bold font-mono" style={{ color: getThreatColor(result.threatLevel) }}>
                        {result.threatLevel}
                      </p>
                      <p className="text-xs text-text-dim mt-1">{getThreatLabel(result.threatLevel)}</p>
                    </Card>
                    <Card className="bg-surface border-border-custom p-4 card-hover-emerald">
                      <div className="flex items-center gap-2 mb-2">
                        <Gauge className="h-4 w-4 text-sayan-amber" />
                        <span className="text-sm font-semibold text-text">Score</span>
                      </div>
                      <p className="text-2xl font-bold font-mono" style={{ color: getThreatColor(result.threatLevel) }}>
                        {result.overallScore}/100
                      </p>
                      <p className="text-xs text-text-dim mt-1">composite threat score</p>
                    </Card>
                    <Card className="bg-surface border-border-custom p-4 card-hover-emerald">
                      <div className="flex items-center gap-2 mb-2">
                        <Timer className="h-4 w-4 text-sayan-emerald" />
                        <span className="text-sm font-semibold text-text">Timestamp</span>
                      </div>
                      <p className="text-sm font-mono text-text">
                        {new Date(result.timestamp).toLocaleTimeString()}
                      </p>
                      <p className="text-xs text-text-dim mt-1">{new Date(result.timestamp).toLocaleDateString()}</p>
                    </Card>
                  </div>
                </div>

                {/* Signal Cards Grid */}
                <div>
                  <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
                    <Activity className="h-5 w-5 text-sayan-emerald" />
                    Detection Signals
                  </h3>
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 max-h-[600px] overflow-y-auto pr-1">
                    {result.signals.map((signal, i) => (
                      <motion.div
                        key={signal.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.03, duration: 0.3 }}
                      >
                        <Card className={`bg-surface border-border-custom p-3 ${signal.passed ? 'card-hover-emerald' : 'card-hover-red'}`}>
                          <div className="flex items-start justify-between gap-2 mb-2">
                            <div className="flex items-center gap-2 min-w-0">
                              {signal.passed ? (
                                <CheckCircle2 className="h-4 w-4 text-sayan-emerald shrink-0" />
                              ) : (
                                <XCircle className="h-4 w-4 text-sayan-red shrink-0" />
                              )}
                              <span className="text-sm font-medium text-text truncate">{signal.name}</span>
                            </div>
                            <CategoryBadge category={signal.category} />
                          </div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs text-text-dim">Value:</span>
                            <code className="text-xs font-mono text-sayan-cyan bg-sayan-cyan/10 px-1.5 py-0.5 rounded truncate max-w-[180px]">
                              {typeof signal.value === 'object' ? JSON.stringify(signal.value) : String(signal.value)}
                            </code>
                          </div>
                          <p className="text-[11px] text-text-dim leading-relaxed">{signal.details}</p>
                        </Card>
                      </motion.div>
                    ))}
                  </div>
                </div>

                {/* Browser Fingerprint */}
                <FingerprintPanel fingerprint={result.fingerprint} />

                {/* WebMCP Analysis */}
                {result.webmcpAnalysis && <WebMCPPanel analysis={result.webmcpAnalysis} />}

                {/* Recommendations */}
                {result.recommendations.length > 0 && (
                  <Card className="bg-surface border-sayan-amber/20 p-6 card-hover-amber">
                    <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
                      <ShieldCheck className="h-5 w-5 text-sayan-amber" />
                      Recommendations
                    </h3>
                    <div className="space-y-3">
                      {result.recommendations.map((rec, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-sayan-amber/5 border border-sayan-amber/10">
                          <ChevronRight className="h-4 w-4 text-sayan-amber mt-0.5 shrink-0" />
                          <p className="text-sm text-text-dim">{rec}</p>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </div>
    </section>
  );
}

function FingerprintPanel({ fingerprint }: { fingerprint: BrowserFingerprint }) {
  const entries: [string, string | number | boolean | null][] = [
    ['User Agent', fingerprint.userAgent.substring(0, 80) + (fingerprint.userAgent.length > 80 ? '...' : '')],
    ['Platform', fingerprint.platform],
    ['Language', fingerprint.language],
    ['Languages', fingerprint.languages.join(', ')],
    ['CPU Cores', fingerprint.hardwareConcurrency],
    ['Device Memory', fingerprint.deviceMemory !== null ? `${fingerprint.deviceMemory} GB` : 'N/A'],
    ['Touch Points', fingerprint.maxTouchPoints],
    ['Color Depth', fingerprint.colorDepth],
    ['Pixel Ratio', fingerprint.pixelRatio],
    ['Screen', `${fingerprint.screenWidth}x${fingerprint.screenHeight}`],
    ['Window', `${fingerprint.windowWidth}x${fingerprint.windowHeight}`],
    ['Timezone', fingerprint.timezone],
    ['WebGL Renderer', fingerprint.webglRenderer],
    ['WebGL Vendor', fingerprint.webglVendor],
    ['Canvas Hash', fingerprint.canvasHash],
    ['Audio Hash', fingerprint.audioHash],
    ['Plugins', fingerprint.plugins.length > 0 ? fingerprint.plugins.join(', ') : 'None'],
    ['Connection', fingerprint.connectionType],
    ['RTT', `${fingerprint.connectionRtt}ms`],
    ['Cookies', fingerprint.cookieEnabled ? 'Enabled' : 'Disabled'],
    ['PDF Viewer', fingerprint.pdfViewerEnabled ? 'Yes' : 'No'],
    ['Do Not Track', fingerprint.doNotTrack || 'Not set'],
  ];

  return (
    <Card className="bg-surface border-border-custom p-6 card-hover-cyan">
      <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
        <Fingerprint className="h-5 w-5 text-sayan-cyan" />
        Browser Fingerprint
      </h3>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {entries.map(([key, val]) => (
          <div key={key} className="flex items-start gap-2 py-1.5 px-2 rounded bg-background/30">
            <span className="text-xs text-text-dim shrink-0 min-w-[90px]">{key}:</span>
            <code className="text-xs font-mono text-sayan-cyan break-all">{String(val)}</code>
          </div>
        ))}
      </div>
    </Card>
  );
}

function WebMCPPanel({ analysis }: { analysis: WebMCPAnalysis }) {
  return (
    <Card className={`bg-surface border-border-custom p-6 card-hover-emerald ${analysis.nativeAvailable ? 'glow-emerald-subtle' : ''}`}>
      <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
        <Webhook className="h-5 w-5 text-sayan-emerald" />
        WebMCP Analysis
      </h3>
      <div className="grid sm:grid-cols-2 gap-4 mb-4">
        <div className="p-3 rounded-lg bg-background/30">
          <p className="text-xs text-text-dim mb-1">Native Available</p>
          <p className={`text-sm font-mono ${analysis.nativeAvailable ? 'text-sayan-emerald' : 'text-text-dim'}`}>
            {analysis.nativeAvailable ? 'Yes' : 'No'}
          </p>
        </div>
        <div className="p-3 rounded-lg bg-background/30">
          <p className="text-xs text-text-dim mb-1">Model Context Type</p>
          <p className="text-sm font-mono text-sayan-cyan">{analysis.modelContextType}</p>
        </div>
        <div className="p-3 rounded-lg bg-background/30">
          <p className="text-xs text-text-dim mb-1">Registered Tools</p>
          <p className="text-sm font-mono text-text">{analysis.registeredToolCount}</p>
        </div>
        <div className="p-3 rounded-lg bg-background/30">
          <p className="text-xs text-text-dim mb-1">Injection Risk</p>
          <Badge
            variant="outline"
            className={`text-xs ${
              analysis.injectionRisk === 'SAFE'
                ? 'text-sayan-emerald border-sayan-emerald/30 bg-sayan-emerald/10'
                : analysis.injectionRisk === 'LOW'
                  ? 'text-green-400 border-green-400/30 bg-green-400/10'
                  : analysis.injectionRisk === 'MEDIUM'
                    ? 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10'
                    : 'text-sayan-red border-sayan-red/30 bg-sayan-red/10'
            }`}
          >
            {analysis.injectionRisk}
          </Badge>
        </div>
      </div>
      {analysis.toolNames.length > 0 && (
        <div className="p-3 rounded-lg bg-background/30">
          <p className="text-xs text-text-dim mb-2">Tool Names</p>
          <div className="flex flex-wrap gap-1.5">
            {analysis.toolNames.map((name) => (
              <Badge key={name} variant="outline" className="text-[10px] text-sayan-cyan border-sayan-cyan/30 bg-sayan-cyan/10">
                {name}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  3. OSINT ATTRIBUTION TRACER                                      */
/* ────────────────────────────────────────────────────────────────── */

function OSINTTracer() {
  const [report, setReport] = useState<AttributionReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runTrace = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await generateAttributionReport();
      setReport(r);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Trace failed');
    } finally {
      setLoading(false);
    }
  }, []);

  const attributionConfig: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    human_user: { color: 'text-sayan-emerald', icon: <UserCheck className="h-5 w-5" />, label: 'Human User' },
    automated_agent: { color: 'text-sayan-amber', icon: <Bot className="h-5 w-5" />, label: 'Automated Agent' },
    datacenter_bot: { color: 'text-sayan-red', icon: <Server className="h-5 w-5" />, label: 'Datacenter Bot' },
    unknown: { color: 'text-text-dim', icon: <CircleDot className="h-5 w-5" />, label: 'Unknown' },
  };

  return (
    <section className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-amber/30 text-sayan-amber bg-sayan-amber/5 mb-4">
              <Globe className="h-3.5 w-3.5 mr-1.5" />
              OSINT Intelligence
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              Attribution Tracer
            </h2>
            <p className="text-text-dim text-lg max-w-xl mx-auto">
              Identify the source and nature of your connection
            </p>
          </div>

          <div className="flex justify-center mb-8">
            <Button
              size="lg"
              disabled={loading}
              onClick={runTrace}
              className="bg-sayan-amber hover:bg-sayan-amber/90 text-[#050507] px-8 h-12 text-base font-semibold"
            >
              {loading ? (
                <>
                  <Activity className="h-4 w-4 mr-2 animate-spin" />
                  Tracing...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4 mr-2" />
                  Run OSINT Trace
                </>
              )}
            </Button>
          </div>

          {error && (
            <Card className="bg-surface border-sayan-red/30 p-4 mb-6 max-w-lg mx-auto">
              <p className="text-sm text-sayan-red flex items-center gap-2">
                <XCircle className="h-4 w-4" />
                {error}
              </p>
            </Card>
          )}

          <AnimatePresence mode="wait">
            {report && (
              <motion.div
                key="osint-result"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.5 }}
                className="space-y-6"
              >
                {/* Overall Attribution */}
                <Card className="bg-surface border-border-custom p-6 flex flex-col items-center card-hover-amber">
                  <p className="text-xs text-text-dim uppercase tracking-wider mb-3">Overall Attribution</p>
                  <div className="flex items-center gap-3">
                    {(() => {
                      const c = attributionConfig[report.overallAttribution] || attributionConfig.unknown;
                      return (
                        <>
                          <span className={c.color}>{c.icon}</span>
                          <span className={`text-2xl font-bold ${c.color}`}>{c.label}</span>
                        </>
                      );
                    })()}
                  </div>
                  <div className="flex items-center gap-2 mt-3">
                    <span className="text-xs text-text-dim">Correlation ID:</span>
                    <code className="text-xs font-mono text-sayan-amber bg-sayan-amber/10 px-2 py-0.5 rounded">
                      {report.correlationId}
                    </code>
                  </div>
                </Card>

                {/* IP Info */}
                {report.trace && (
                  <Card className="bg-surface border-border-custom p-6 card-hover-amber">
                    <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
                      <MapPin className="h-5 w-5 text-sayan-amber" />
                      IP Geolocation
                    </h3>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-4">
                      {[
                        ['IP Address', report.trace.ipAddress],
                        ['ISP', report.trace.isp],
                        ['Organization', report.trace.org],
                        ['City', report.trace.city],
                        ['Country', report.trace.country],
                        ['ASN', report.trace.asn],
                        ['Timezone', report.trace.timezone],
                        ['Region', report.trace.region],
                      ].map(([k, v]) => (
                        <div key={k} className="p-2.5 rounded-lg bg-background/30">
                          <p className="text-[10px] text-text-dim uppercase tracking-wider mb-0.5">{k}</p>
                          <p className="text-sm font-mono text-text break-all">{v}</p>
                        </div>
                      ))}
                    </div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="text-xs text-text-dim">Source Type:</span>
                      <SourceTypeBadge type={report.trace.sourceType} />
                      {report.trace.isDataCenter && (
                        <Badge variant="outline" className="text-[10px] text-sayan-red border-sayan-red/30 bg-sayan-red/10">
                          <Building2 className="h-3 w-3 mr-1" /> Data Center
                        </Badge>
                      )}
                      {report.trace.isVPN && (
                        <Badge variant="outline" className="text-[10px] text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10">
                          <ShieldAlert className="h-3 w-3 mr-1" /> VPN
                        </Badge>
                      )}
                    </div>
                  </Card>
                )}

                {/* Risk Factors */}
                {report.riskFactors.length > 0 && (
                  <Card className="bg-surface border-border-custom p-6 card-hover-red">
                    <h3 className="text-lg font-semibold text-text mb-4 flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-sayan-amber" />
                      Risk Factors
                    </h3>
                    <div className="space-y-3">
                      {report.riskFactors.map((rf, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-background/30">
                          <RiskFactorBadge severity={rf.severity} />
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-text">{rf.factor}</p>
                            <p className="text-xs text-text-dim mt-0.5">{rf.description}</p>
                            <p className="text-[11px] text-text-dim mt-1 font-mono">{rf.evidence}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* TLS / HTTP2 Fingerprint */}
                <div className="grid md:grid-cols-2 gap-4">
                  {report.tlsFingerprint && (
                    <Card className="bg-surface border-border-custom p-6 card-hover-cyan">
                      <h3 className="text-sm font-semibold text-text mb-3 flex items-center gap-2">
                        <Lock className="h-4 w-4 text-sayan-cyan" />
                        TLS Fingerprint
                      </h3>
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-text-dim w-16">JA3:</span>
                          <code className="text-[10px] font-mono text-sayan-cyan bg-sayan-cyan/10 px-1.5 py-0.5 rounded truncate">
                            {report.tlsFingerprint.ja3Hash}
                          </code>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-text-dim w-16">JA4:</span>
                          <code className="text-[10px] font-mono text-sayan-cyan bg-sayan-cyan/10 px-1.5 py-0.5 rounded truncate">
                            {report.tlsFingerprint.ja4Hash}
                          </code>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-text-dim w-16">Protocol:</span>
                          <span className="text-xs font-mono text-text">{report.tlsFingerprint.protocol}</span>
                        </div>
                      </div>
                    </Card>
                  )}
                  {report.http2Fingerprint && (
                    <Card className="bg-surface border-border-custom p-6 card-hover-cyan">
                      <h3 className="text-sm font-semibold text-text mb-3 flex items-center gap-2">
                        <Wifi className="h-4 w-4 text-sayan-cyan" />
                        HTTP/2 Fingerprint
                      </h3>
                      <div className="space-y-2">
                        {Object.entries(report.http2Fingerprint.settingsFrame).map(([k, v]) => (
                          <div key={k} className="flex items-center gap-2">
                            <span className="text-[10px] text-text-dim w-36 truncate">{k}:</span>
                            <code className="text-[10px] font-mono text-sayan-cyan">{v}</code>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>

                {/* Browser Profile */}
                <Card className="bg-surface border-border-custom p-6 card-hover-emerald">
                  <h3 className="text-sm font-semibold text-text mb-3 flex items-center gap-2">
                    <Monitor className="h-4 w-4 text-sayan-emerald" />
                    Browser Profile
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                    {Object.entries(report.browserProfile).map(([k, v]) => (
                      <div key={k} className="p-2 rounded bg-background/30">
                        <p className="text-[10px] text-text-dim uppercase tracking-wider mb-0.5">
                          {k.replace(/([A-Z])/g, ' $1').trim()}
                        </p>
                        <p className="text-xs font-mono text-text truncate">{String(v)}</p>
                      </div>
                    ))}
                  </div>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  4. MCP CVE DATABASE                                              */
/* ────────────────────────────────────────────────────────────────── */

function MCPcveDatabase() {
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');
  const sorted = [...MCP_CVE_DATABASE].sort((a, b) =>
    sortDir === 'desc' ? b.severity - a.severity : a.severity - b.severity
  );

  return (
    <section className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-red/30 text-sayan-red bg-sayan-red/5 mb-4">
              <FileWarning className="h-3.5 w-3.5 mr-1.5" />
              Vulnerability Database
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              MCP CVE Database
            </h2>
            <p className="text-text-dim text-lg max-w-xl mx-auto">
              Known vulnerabilities in the MCP ecosystem with digital drone relevance
            </p>
          </div>

          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-text-dim">
              {MCP_CVE_DATABASE.length} vulnerabilities cataloged
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))}
              className="border-border-custom text-text-dim hover:text-text hover:bg-surface-hover text-xs"
            >
              Severity: {sortDir === 'desc' ? 'High → Low' : 'Low → High'}
            </Button>
          </div>

          <div className="rounded-xl border border-border-custom overflow-hidden bg-surface/50">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-border-custom hover:bg-transparent">
                    <TableHead className="text-text-dim font-semibold text-xs">CVE ID</TableHead>
                    <TableHead className="text-text-dim font-semibold text-xs">Severity</TableHead>
                    <TableHead className="text-text-dim font-semibold text-xs">Component</TableHead>
                    <TableHead className="text-text-dim font-semibold text-xs">Description</TableHead>
                    <TableHead className="text-text-dim font-semibold text-xs">Status</TableHead>
                    <TableHead className="text-text-dim font-semibold text-xs">Digital Drone Relevance</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sorted.map((cve) => (
                    <TableRow key={cve.id} className="border-border-custom/50 hover:bg-surface-hover/30">
                      <TableCell className="font-mono text-xs text-sayan-cyan whitespace-nowrap">{cve.id}</TableCell>
                      <TableCell>
                        <SeverityBadge severity={cve.severity} />
                      </TableCell>
                      <TableCell className="text-xs text-text whitespace-nowrap">{cve.component}</TableCell>
                      <TableCell className="text-xs text-text-dim max-w-[200px]">{cve.description}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${
                            cve.status.includes('Patched')
                              ? 'text-sayan-emerald border-sayan-emerald/30 bg-sayan-emerald/10'
                              : cve.status.includes('Active')
                                ? 'text-sayan-red border-sayan-red/30 bg-sayan-red/10'
                                : 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10'
                          }`}
                        >
                          {cve.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-[11px] text-text-dim max-w-[250px]">{cve.digitalDroneRelevance}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  5. THREAT INTELLIGENCE BRIEFING                                  */
/* ────────────────────────────────────────────────────────────────── */

const threatStats = [
  { value: '1,400%', label: 'increase in AI agent bot traffic (2025)', color: 'text-sayan-red', icon: <Activity className="h-5 w-5" /> },
  { value: '135,000+', label: 'exposed OpenClaw agent instances', color: 'text-sayan-amber', icon: <Server className="h-5 w-5" /> },
  { value: '2.8%', label: 'of sites can detect AI agent traffic', color: 'text-sayan-cyan', icon: <Eye className="h-5 w-5" /> },
  { value: '14+', label: 'CVEs in MCP ecosystem (2025-2026)', color: 'text-sayan-red', icon: <Bug className="h-5 w-5" /> },
];

const attackChain = [
  { label: 'Attacker', color: 'text-sayan-red', icon: <ShieldX className="h-4 w-4" /> },
  { label: 'MCP Tool Poisoning', color: 'text-sayan-amber', icon: <FileWarning className="h-4 w-4" /> },
  { label: 'AI Agent Compromised', color: 'text-sayan-red', icon: <Bot className="h-4 w-4" /> },
  { label: 'Browser Access + User Credentials', color: 'text-sayan-amber', icon: <Chrome className="h-4 w-4" /> },
  { label: 'Data Exfiltration via Covert Channels', color: 'text-sayan-red', icon: <Network className="h-4 w-4" /> },
  { label: 'Attacker Receives Data', color: 'text-sayan-red', icon: <ShieldX className="h-4 w-4" /> },
];

const hardToDetectReasons = [
  { icon: <Fingerprint className="h-5 w-5" />, title: 'Real Browser Fingerprints', desc: 'Agents use real Chrome instances with genuine browser fingerprints — identical to human users' },
  { icon: <KeyRound className="h-5 w-5" />, title: 'Valid Session Credentials', desc: 'Agents inherit the user\'s authenticated session — cookies, tokens, and all' },
  { icon: <MousePointer2 className="h-5 w-5" />, title: 'Human-Like Interactions', desc: 'AI agents click, scroll, and type with near-human behavioral patterns' },
  { icon: <Network className="h-5 w-5" />, title: 'Encrypted Covert Channels', desc: 'WebRTC, Service Workers, and WebGPU enable data exfiltration invisible to network monitors' },
  { icon: <Webhook className="h-5 w-5" />, title: 'MCP Tool Injection', desc: 'Mid-session tool poisoning silently redirects agent behavior without any visible change' },
  { icon: <Cloud className="h-5 w-5" />, title: 'Cloud-Native Infrastructure', desc: 'Agents run on legitimate cloud platforms — indistinguishable from normal automation traffic' },
];

function ThreatIntel() {
  return (
    <section id="threat-intel" className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-red/30 text-sayan-red bg-sayan-red/5 mb-4">
              <AlertTriangle className="h-3.5 w-3.5 mr-1.5" />
              Threat Briefing
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              Digital Drone Threat Assessment
            </h2>
            <p className="text-text-dim text-lg max-w-xl mx-auto">
              AI agents with browser access are being used as undetectable attack vectors
            </p>
          </div>

          {/* Summary Card */}
          <Card className="bg-surface border-sayan-red/20 p-6 mb-8 card-hover-red glow-red-subtle">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-sayan-red/10 border border-sayan-red/20 shrink-0">
                <ShieldAlert className="h-6 w-6 text-sayan-red" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-text mb-2">Critical Finding</h3>
                <p className="text-sm text-text-dim leading-relaxed">
                  AI agents with browser access are being used as undetectable attack vectors.
                  These &ldquo;digital drones&rdquo; operate with full user credentials, real browser
                  fingerprints, and human-like behavioral patterns — making them invisible to
                  conventional bot detection systems. The MCP (Model Context Protocol) ecosystem
                  has introduced new attack surfaces that enable tool poisoning, mid-session
                  injection, and data exfiltration through covert channels.
                </p>
              </div>
            </div>
          </Card>

          {/* Key Statistics */}
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
            {threatStats.map((stat, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1, duration: 0.4 }}
              >
                <Card className="bg-surface border-border-custom p-5 text-center card-hover-emerald">
                  <div className="flex justify-center mb-2 text-text-dim">{stat.icon}</div>
                  <p className={`text-3xl md:text-4xl font-bold font-mono ${stat.color} stat-appear`}>
                    {stat.value}
                  </p>
                  <p className="text-xs text-text-dim mt-2">{stat.label}</p>
                </Card>
              </motion.div>
            ))}
          </div>

          {/* Attack Chain */}
          <Card className="bg-surface border-border-custom p-6 mb-10">
            <h3 className="text-lg font-semibold text-text mb-6 flex items-center gap-2">
              <GitBranch className="h-5 w-5 text-sayan-red" />
              Attack Chain Visualization
            </h3>
            <div className="flex flex-wrap items-center justify-center gap-2 md:gap-0">
              {attackChain.map((step, i) => (
                <div key={i} className="flex items-center gap-2">
                  <div className="flex flex-col items-center gap-1 px-3 py-2 rounded-lg bg-background/30 border border-border-custom min-w-[100px]">
                    <span className={step.color}>{step.icon}</span>
                    <span className={`text-[10px] text-center ${step.color} font-medium leading-tight`}>
                      {step.label}
                    </span>
                  </div>
                  {i < attackChain.length - 1 && (
                    <ChevronRight className="h-4 w-4 text-text-dim flow-arrow shrink-0 hidden md:block" />
                  )}
                  {i < attackChain.length - 1 && (
                    <div className="w-2 h-2 rounded-full bg-sayan-red/30 md:hidden flow-arrow" />
                  )}
                </div>
              ))}
            </div>
          </Card>

          {/* Why Digital Drones Are Hard to Detect */}
          <h3 className="text-xl font-semibold text-text mb-6 flex items-center gap-2">
            <Eye className="h-5 w-5 text-sayan-cyan" />
            Why Digital Drones Are Hard to Detect
          </h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {hardToDetectReasons.map((reason, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08, duration: 0.4 }}
              >
                <Card className="bg-surface border-border-custom p-5 card-hover-cyan h-full">
                  <div className="text-sayan-cyan mb-3">{reason.icon}</div>
                  <h4 className="text-sm font-semibold text-text mb-2">{reason.title}</h4>
                  <p className="text-xs text-text-dim leading-relaxed">{reason.desc}</p>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  6. guest271314 ANALYSIS                                          */
/* ────────────────────────────────────────────────────────────────── */

const guestRepos = [
  {
    name: 'NativeTransferableStreams',
    description: 'Execute arbitrary shell scripts from browser at any origin',
    threat: 'CRITICAL',
    threatColor: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10',
    technique: 'Transferable Streams + NativeMessaging',
    icon: <Terminal className="h-4 w-4" />,
  },
  {
    name: 'socket.iwa',
    description: 'Browser becomes a full TCP/UDP server — Tor bootstraps in WASM',
    threat: 'CRITICAL',
    threatColor: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10',
    technique: 'Isolated Web App + Direct Sockets',
    icon: <Network className="h-4 w-4" />,
  },
  {
    name: 'HeadlessDetectJS',
    description: '6-signal headless detection scoring system',
    threat: 'RESEARCH',
    threatColor: 'text-sayan-cyan border-sayan-cyan/30 bg-sayan-cyan/10',
    technique: 'Composite signal detection',
    icon: <Eye className="h-4 w-4" />,
  },
  {
    name: 'remove-csp-header',
    description: 'Strips CSP headers, neutralizing browser XSS defenses',
    threat: 'HIGH',
    threatColor: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10',
    technique: 'Service Worker header manipulation',
    icon: <ShieldX className="h-4 w-4" />,
  },
  {
    name: 'isolated-web-app-utilities',
    description: 'IWA access from any page → Direct Sockets → raw TCP/UDP',
    threat: 'CRITICAL',
    threatColor: 'text-sayan-red border-sayan-red/30 bg-sayan-red/10',
    technique: 'IWA boundary bypass + Direct Sockets API',
    icon: <Code2 className="h-4 w-4" />,
  },
  {
    name: 'WebExtensionMessageStream',
    description: 'Full-duplex streaming via Mojo IPC + Transferable Streams',
    threat: 'HIGH',
    threatColor: 'text-sayan-amber border-sayan-amber/30 bg-sayan-amber/10',
    technique: 'Chrome Extension Mojo IPC bridge',
    icon: <Layers className="h-4 w-4" />,
  },
];

function GuestAnalysis() {
  return (
    <section className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-cyan/30 text-sayan-cyan bg-sayan-cyan/5 mb-4">
              <Framer className="h-3.5 w-3.5 mr-1.5" />
              Security Research
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              guest271314: Browser Security&apos;s Most Creative Researcher
            </h2>
            <p className="text-text-dim text-lg max-w-2xl mx-auto">
              Demonstrating how browser API seams can be exploited to create channels no single API was designed to enable
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
            {guestRepos.map((repo, i) => (
              <motion.div
                key={repo.name}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08, duration: 0.4 }}
              >
                <Card className="bg-surface border-border-custom p-5 card-hover-cyan h-full">
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sayan-cyan">{repo.icon}</span>
                      <h4 className="text-sm font-semibold text-text font-mono">{repo.name}</h4>
                    </div>
                    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 shrink-0 ${repo.threatColor}`}>
                      {repo.threat}
                    </Badge>
                  </div>
                  <p className="text-xs text-text-dim leading-relaxed mb-3">{repo.description}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-text-dim">Key Technique:</span>
                    <code className="text-[10px] font-mono text-sayan-cyan bg-sayan-cyan/10 px-1.5 py-0.5 rounded">
                      {repo.technique}
                    </code>
                  </div>
                </Card>
              </motion.div>
            ))}
          </div>

          <Card className="bg-surface border-sayan-cyan/20 p-6 card-hover-cyan">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-lg bg-sayan-cyan/10 border border-sayan-cyan/20 shrink-0">
                <Info className="h-5 w-5 text-sayan-cyan" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-text mb-2">Key Insight</h4>
                <p className="text-sm text-text-dim leading-relaxed italic">
                  &ldquo;The browser&apos;s security model has many seams where APIs meet, and these seams can be
                  exploited to create channels that no single API was designed to enable.&rdquo;
                </p>
                <p className="text-xs text-text-dim mt-2">
                  — Summarizing guest271314&apos;s body of work on browser API boundary exploitation
                </p>
              </div>
            </div>
          </Card>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  7. SUPER SAYAN FEATURES                                          */
/* ────────────────────────────────────────────────────────────────── */

const offensiveFeatures = [
  { icon: <Eye className="h-5 w-5" />, title: 'Browser Observation Scanner', desc: 'See exactly what your browser reveals about you' },
  { icon: <Webhook className="h-5 w-5" />, title: 'WebMCP Tool Surface Analyzer', desc: 'Detect tool injection and poisoning in real-time' },
  { icon: <Network className="h-5 w-5" />, title: 'Covert Channel Detector', desc: 'Identify WebRTC, SW, SAB, WebGPU exfiltration vectors' },
  { icon: <KeyRound className="h-5 w-5" />, title: 'Session Hijack Visualizer', desc: 'Map the attack surface of authenticated sessions' },
];

const defensiveFeatures = [
  { icon: <ShieldCheck className="h-5 w-5" />, title: 'Headless Detection Engine', desc: '10+ signal composite detection with scoring algorithm' },
  { icon: <MousePointer2 className="h-5 w-5" />, title: 'AI Agent Behavioral Fingerprinting', desc: 'Mouse straightness, velocity CV, click pattern analysis' },
  { icon: <Activity className="h-5 w-5" />, title: 'WebMCP Tool Invocation Monitor', desc: 'Wrap execute callbacks for real-time tool observation' },
  { icon: <Chrome className="h-5 w-5" />, title: 'Chrome Extension "Glow" System', desc: 'Elements accessed by agents glow red; pages glow on headless access' },
  { icon: <Bug className="h-5 w-5" />, title: 'MCP Vulnerability Scanner', desc: '14+ CVEs cataloged with digital drone relevance scoring' },
];

const osintFeatures = [
  { icon: <MapPin className="h-5 w-5" />, title: 'IP/ASN Source Attribution', desc: 'Residential vs datacenter vs VPN classification' },
  { icon: <Lock className="h-5 w-5" />, title: 'TLS Fingerprinting (JA3/JA4)', desc: 'Server-side detection that cannot be forged client-side' },
  { icon: <Wifi className="h-5 w-5" />, title: 'HTTP/2 Fingerprinting', desc: 'SETTINGS frame analysis distinguishes Chrome from automation' },
  { icon: <Timer className="h-5 w-5" />, title: 'Timestamp Correlation', desc: 'Detect coordinated bot activity across sessions' },
];

function SuperSayanFeatures() {
  return (
    <section className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-emerald/30 text-sayan-emerald bg-sayan-emerald/5 mb-4">
              <Zap className="h-3.5 w-3.5 mr-1.5" />
              Feature Suite
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              SuperSayan Features
            </h2>
            <p className="text-text-dim text-lg max-w-xl mx-auto">
              A comprehensive security intelligence platform for the agentic web
            </p>
          </div>

          <Tabs defaultValue="defensive" className="w-full">
            <TabsList className="bg-surface border border-border-custom w-full grid grid-cols-3 mb-8">
              <TabsTrigger
                value="offensive"
                className="text-xs data-[state=active]:bg-sayan-red/10 data-[state=active]:text-sayan-red"
              >
                <ShieldX className="h-3.5 w-3.5 mr-1.5" />
                Offensive/Research
              </TabsTrigger>
              <TabsTrigger
                value="defensive"
                className="text-xs data-[state=active]:bg-sayan-emerald/10 data-[state=active]:text-sayan-emerald"
              >
                <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />
                Defensive
              </TabsTrigger>
              <TabsTrigger
                value="osint"
                className="text-xs data-[state=active]:bg-sayan-amber/10 data-[state=active]:text-sayan-amber"
              >
                <Globe className="h-3.5 w-3.5 mr-1.5" />
                OSINT/Tracking
              </TabsTrigger>
            </TabsList>

            <TabsContent value="offensive">
              <div className="grid sm:grid-cols-2 gap-4">
                {offensiveFeatures.map((feat, i) => (
                  <motion.div
                    key={feat.title}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.1, duration: 0.3 }}
                  >
                    <Card className="bg-surface border-border-custom p-5 card-hover-red h-full">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-sayan-red/10 border border-sayan-red/20 shrink-0 text-sayan-red">
                          {feat.icon}
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-text mb-1">{feat.title}</h4>
                          <p className="text-xs text-text-dim leading-relaxed">{feat.desc}</p>
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="defensive">
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {defensiveFeatures.map((feat, i) => (
                  <motion.div
                    key={feat.title}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.1, duration: 0.3 }}
                  >
                    <Card className="bg-surface border-border-custom p-5 card-hover-emerald h-full">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-sayan-emerald/10 border border-sayan-emerald/20 shrink-0 text-sayan-emerald">
                          {feat.icon}
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-text mb-1">{feat.title}</h4>
                          <p className="text-xs text-text-dim leading-relaxed">{feat.desc}</p>
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="osint">
              <div className="grid sm:grid-cols-2 gap-4">
                {osintFeatures.map((feat, i) => (
                  <motion.div
                    key={feat.title}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.1, duration: 0.3 }}
                  >
                    <Card className="bg-surface border-border-custom p-5 card-hover-amber h-full">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-sayan-amber/10 border border-sayan-amber/20 shrink-0 text-sayan-amber">
                          {feat.icon}
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-text mb-1">{feat.title}</h4>
                          <p className="text-xs text-text-dim leading-relaxed">{feat.desc}</p>
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  8. CHROME EXTENSION CONCEPT                                      */
/* ────────────────────────────────────────────────────────────────── */

const extensionFeatures = [
  { icon: <Eye className="h-4 w-4" />, title: 'MutationObserver', desc: 'Watches for programmatic DOM changes in real-time' },
  { icon: <MousePointer2 className="h-4 w-4" />, title: 'navigator.userActivation', desc: 'Distinguishes human vs programmatic actions' },
  { icon: <Activity className="h-4 w-4" />, title: 'PerformanceObserver', desc: 'Detects burst API call patterns from automation' },
  { icon: <Webhook className="h-4 w-4" />, title: 'WebMCP toolchange', desc: 'Monitors tool injection and modification events' },
  { icon: <Zap className="h-4 w-4" />, title: 'Visual CSS Overlay', desc: 'Configurable glow intensity for detected interactions' },
  { icon: <FileWarning className="h-4 w-4" />, title: 'Incident Report', desc: 'Exportable report with OSINT attribution data' },
];

function ChromeExtensionConcept() {
  return (
    <section className="py-16 px-4">
      <div className="max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-80px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="text-center mb-10">
            <Badge variant="outline" className="border-sayan-red/30 text-sayan-red bg-sayan-red/5 mb-4">
              <Chrome className="h-3.5 w-3.5 mr-1.5" />
              Chrome Extension
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold text-text mb-3">
              The &ldquo;Glow&rdquo; Extension
            </h2>
            <p className="text-text-dim text-lg max-w-xl mx-auto">
              Visual detection of AI agent and automated browser interactions
            </p>
          </div>

          <div className="grid lg:grid-cols-[1fr_1fr] gap-8 items-start">
            {/* Visual Mockup */}
            <Card className="bg-surface border-sayan-red/20 p-0 overflow-hidden glow-red-subtle">
              <div className="p-3 border-b border-border-custom flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-sayan-red/60" />
                  <div className="w-3 h-3 rounded-full bg-sayan-amber/60" />
                  <div className="w-3 h-3 rounded-full bg-sayan-emerald/60" />
                </div>
                <div className="flex-1 bg-background/50 rounded px-3 py-1 text-[10px] font-mono text-text-dim text-center">
                  example.com — AI Agent Detected
                </div>
                <Badge variant="outline" className="text-[9px] text-sayan-red border-sayan-red/30 bg-sayan-red/10 px-1.5 py-0">
                  GLOW ACTIVE
                </Badge>
              </div>
              <div className="p-6 relative">
                {/* Mock page content */}
                <div className="space-y-4 relative">
                  <div className="h-4 bg-text-dim/10 rounded w-3/4" />
                  <div className="h-3 bg-text-dim/5 rounded w-full" />
                  <div className="h-3 bg-text-dim/5 rounded w-5/6" />

                  {/* Element being accessed by agent — glowing red */}
                  <div className="p-4 rounded-lg border-2 border-sayan-red/50 bg-sayan-red/5 glow-pulse-red">
                    <div className="h-3 bg-sayan-red/20 rounded w-2/3 mb-2" />
                    <div className="h-3 bg-sayan-red/15 rounded w-4/5 mb-2" />
                    <div className="h-8 bg-sayan-red/10 rounded w-1/3" />
                    <div className="absolute -top-1 -right-1 bg-sayan-red text-[8px] text-white px-1.5 py-0.5 rounded font-mono">
                      AGENT ACCESS
                    </div>
                  </div>

                  <div className="h-3 bg-text-dim/5 rounded w-full" />

                  {/* Another element being accessed */}
                  <div className="p-3 rounded border border-sayan-red/30 bg-sayan-red/3 glow-pulse-red" style={{ animationDelay: '0.5s' }}>
                    <div className="h-3 bg-sayan-red/15 rounded w-1/2 mb-2" />
                    <div className="h-6 bg-sayan-red/10 rounded w-1/4" />
                  </div>

                  <div className="h-3 bg-text-dim/5 rounded w-3/4" />
                </div>

                {/* Page border glow indicator */}
                <div className="absolute inset-0 rounded-lg border-2 border-sayan-red/20 border-glow-animate-red pointer-events-none" />
              </div>
            </Card>

            {/* Description + Features */}
            <div className="space-y-6">
              <Card className="bg-surface border-border-custom p-6">
                <h3 className="text-lg font-semibold text-text mb-3 flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-sayan-red" />
                  How It Works
                </h3>
                <p className="text-sm text-text-dim leading-relaxed mb-4">
                  When a Chrome headless shell or AI agent accesses an element, it glows red.
                  When a page is accessed by an automated browser, the entire page gets a subtle
                  red border glow. The extension monitors DOM mutations, user activation states,
                  and API call patterns to distinguish human from agent interactions in real-time.
                </p>
                <div className="p-3 rounded-lg bg-sayan-red/5 border border-sayan-red/10">
                  <p className="text-xs text-text-dim font-mono leading-relaxed">
                    <span className="text-sayan-red">{'// Agent accesses element'}</span><br />
                    MutationObserver → DOM change detected<br />
                    navigator.userActivation → isActive: <span className="text-sayan-red">false</span><br />
                    → Element glows <span className="text-sayan-red">red</span> (programmatic)<br /><br />
                    <span className="text-sayan-emerald">{'// Human clicks element'}</span><br />
                    userActivation → isActive: <span className="text-sayan-emerald">true</span><br />
                    → Element stays <span className="text-sayan-emerald">normal</span> (human)
                  </p>
                </div>
              </Card>

              <div className="grid grid-cols-2 gap-3">
                {extensionFeatures.map((feat, i) => (
                  <motion.div
                    key={feat.title}
                    initial={{ opacity: 0, y: 10 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: i * 0.08, duration: 0.3 }}
                  >
                    <Card className="bg-surface border-border-custom p-3 card-hover-red h-full">
                      <div className="text-sayan-red mb-1.5">{feat.icon}</div>
                      <h4 className="text-xs font-semibold text-text mb-0.5">{feat.title}</h4>
                      <p className="text-[10px] text-text-dim leading-relaxed">{feat.desc}</p>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  9. FOOTER                                                        */
/* ────────────────────────────────────────────────────────────────── */

function Footer() {
  return (
    <footer className="border-t border-border-custom bg-surface/50 mt-auto">
      <div className="max-w-6xl mx-auto px-4 py-10">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="text-center md:text-left">
            <h3 className="text-lg font-bold animate-gradient-sayan inline-block">
              SuperSayanMCP
            </h3>
            <p className="text-sm text-text-dim mt-1">
              WebMCP Security Intelligence
            </p>
            <p className="text-xs text-text-dim mt-2 max-w-md">
              Built for the agentic web. Defend against digital drones.
            </p>
          </div>

          <div className="flex items-center gap-6">
            <a
              href="#"
              className="text-sm text-text-dim hover:text-sayan-emerald transition-colors flex items-center gap-1.5"
            >
              <Github className="h-4 w-4" />
              GitHub
            </a>
            <a
              href="#"
              className="text-sm text-text-dim hover:text-sayan-emerald transition-colors flex items-center gap-1.5"
            >
              <BookOpen className="h-4 w-4" />
              Documentation
            </a>
            <a
              href="#"
              className="text-sm text-text-dim hover:text-sayan-amber transition-colors flex items-center gap-1.5"
            >
              <AlertTriangle className="h-4 w-4" />
              Security Advisory
            </a>
          </div>
        </div>
        <Separator className="bg-border-custom my-6" />
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2">
          <p className="text-xs text-text-dim">
            &copy; 2026 SuperSayanMCP. MIT License.
          </p>
          <p className="text-xs text-text-dim flex items-center gap-1">
            <Scale className="h-3 w-3" />
            Open source security research
          </p>
        </div>
      </div>
    </footer>
  );
}

/* ────────────────────────────────────────────────────────────────── */
/*  MAIN PAGE                                                        */
/* ────────────────────────────────────────────────────────────────── */

export default function SuperSayanMCPPage() {
  return (
    <div className="min-h-screen flex flex-col bg-[#050507] grid-bg">
      <HeroSection />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <DetectionDashboard />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <OSINTTracer />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <MCPcveDatabase />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <ThreatIntel />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <GuestAnalysis />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <SuperSayanFeatures />
      <Separator className="bg-border-custom max-w-6xl mx-auto w-full" />
      <ChromeExtensionConcept />
      <Footer />
    </div>
  );
}
