import { useEffect, useMemo, useRef, useState } from 'react';
import {
  buildLegacyPermalinkUrl,
  buildSession,
  buildSessionPermalinkUrl,
  decodeSessionPermalink,
  EBGP_IPV4_BASIC_SCENARIO,
  encodeSessionPermalink,
  exportSessionPcap,
  getBuiltinScenario,
  isLegacyPermalinkHash,
  type SessionConfig,
  type SessionEvent,
  type SessionTrace,
} from './core/session';
import { BgpMessageInspector } from './ui/bgp/BgpMessageInspector';
import { ConfigPanel } from './ui/bgp/ConfigPanel';
import { DecodeBgpHexPanel } from './ui/bgp/DecodeBgpHexPanel';
import { NegotiatedStatePanel } from './ui/bgp/NegotiatedStatePanel';
import { SessionLadder } from './ui/bgp/SessionLadder';

interface InitialAppState {
  readonly scenarioId: string;
  readonly config: SessionConfig;
  readonly events: readonly SessionEvent[];
  readonly permalinkError: string | null;
  readonly legacyLinkHref: string | null;
}

function readInitialAppState(): InitialAppState {
  const fallback = (
    permalinkError: string | null,
    legacyLinkHref: string | null,
  ): InitialAppState => ({
    scenarioId: EBGP_IPV4_BASIC_SCENARIO.id,
    config: EBGP_IPV4_BASIC_SCENARIO.config,
    events: EBGP_IPV4_BASIC_SCENARIO.events,
    permalinkError,
    legacyLinkHref,
  });

  if (typeof window === 'undefined') {
    return fallback(null, null);
  }

  const hash = window.location.hash;
  if (hash.length === 0 || hash === '#') {
    return fallback(null, null);
  }

  if (isLegacyPermalinkHash(hash)) {
    return fallback(null, buildLegacyPermalinkUrl(hash));
  }

  const decoded = decodeSessionPermalink(hash);
  if (!decoded.ok) {
    return fallback(`Invalid session link: ${decoded.error}`, null);
  }

  return {
    scenarioId: decoded.value.scenarioId,
    config: decoded.value.config,
    events: decoded.value.events,
    permalinkError: null,
    legacyLinkHref: null,
  };
}

function defaultSelectedStepIndex(trace: SessionTrace): number {
  const firstBgp = trace.steps.find((s) => s.kind === 'bgp');
  return firstBgp ? firstBgp.index : 0;
}

export function App() {
  const initialRef = useRef<InitialAppState | null>(null);
  if (initialRef.current === null) {
    initialRef.current = readInitialAppState();
  }
  const initial = initialRef.current;

  const [scenarioId, setScenarioId] = useState(initial.scenarioId);
  const [config, setConfig] = useState<SessionConfig>(initial.config);
  const [events, setEvents] = useState<readonly SessionEvent[]>(initial.events);
  const [showTcpSteps, setShowTcpSteps] = useState(true);
  const [showHexDecoder, setShowHexDecoder] = useState(false);
  const [permalinkError, setPermalinkError] = useState<string | null>(initial.permalinkError);
  const [legacyLinkHref, setLegacyLinkHref] = useState<string | null>(initial.legacyLinkHref);
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'error'>('idle');
  const copyTimerRef = useRef<number | null>(null);

  const lastValidTraceRef = useRef<SessionTrace | null>(null);

  const buildResult = useMemo(() => {
    try {
      const trace = buildSession(config, events);
      return { ok: true as const, trace, error: null };
    } catch (error) {
      return {
        ok: false as const,
        trace: lastValidTraceRef.current,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }, [config, events]);

  if (buildResult.ok) {
    lastValidTraceRef.current = buildResult.trace;
  }

  const trace: SessionTrace =
    buildResult.trace ??
    buildSession(EBGP_IPV4_BASIC_SCENARIO.config, EBGP_IPV4_BASIC_SCENARIO.events);

  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(() =>
    defaultSelectedStepIndex(trace),
  );

  // Keep selected step valid if config edits shorten the trace
  const safeSelectedIndex =
    selectedStepIndex >= 0 && selectedStepIndex < trace.steps.length
      ? selectedStepIndex
      : defaultSelectedStepIndex(trace);
  const selectedStep = trace.steps[safeSelectedIndex] ?? trace.steps[0];

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const handleSelectScenario = (id: string) => {
    const found = getBuiltinScenario(id) ?? EBGP_IPV4_BASIC_SCENARIO;
    setScenarioId(found.id);
    setConfig(found.config);
    setEvents(found.events);
    setPermalinkError(null);
    setLegacyLinkHref(null);
    const nextTrace = buildSession(found.config, found.events);
    setSelectedStepIndex(defaultSelectedStepIndex(nextTrace));
  };

  const handleResetScenario = () => {
    handleSelectScenario(scenarioId);
  };

  const handleDownloadPcap = () => {
    const pcapBytes = exportSessionPcap(trace);
    const blob = new Blob([pcapBytes.slice()], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `tsumiki-${scenarioId}.pcap`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const handleCopyLink = async () => {
    const fragment = encodeSessionPermalink({ scenarioId, config, events });
    const fullUrl = buildSessionPermalinkUrl(
      window.location.origin,
      window.location.pathname,
      fragment,
    );
    window.history.replaceState(null, '', `#${fragment}`);
    try {
      await navigator.clipboard.writeText(fullUrl);
      setCopyStatus('copied');
    } catch {
      setCopyStatus('error');
    }
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopyStatus('idle');
      copyTimerRef.current = null;
    }, 2000);
  };

  const selectedBgpBytes =
    selectedStep && selectedStep.kind === 'bgp' && selectedStep.bgpOffset !== undefined
      ? selectedStep.frameBytes.slice(selectedStep.bgpOffset)
      : undefined;

  return (
    <div className="bgp-app">
      <header className="bgp-topbar">
        <div className="bgp-brand">
          <h1 className="bgp-title">tsumiki</h1>
          <p className="bgp-subtitle">
            Learn what&apos;s inside BGP messages before you open a capture.
          </p>
        </div>

        <div className="bgp-actions" role="toolbar" aria-label="Session Actions">
          <button type="button" className="bgp-action-btn is-primary" onClick={handleDownloadPcap}>
            Download .pcap
          </button>
          <button type="button" className="bgp-action-btn" onClick={handleCopyLink}>
            {copyStatus === 'copied'
              ? 'Copied Link!'
              : copyStatus === 'error'
                ? 'Link Updated in URL'
                : 'Copy Link'}
          </button>
          <button
            type="button"
            className={`bgp-action-btn${showHexDecoder ? ' is-active' : ''}`}
            aria-pressed={showHexDecoder}
            onClick={() => setShowHexDecoder((prev) => !prev)}
          >
            Decode BGP hex
          </button>
          <a className="bgp-legacy-link" href="./legacy/">
            Legacy Packet Builder
          </a>
        </div>
      </header>

      {legacyLinkHref && (
        <div className="bgp-banner is-info" role="status">
          <span>
            This link uses the legacy general-purpose packet builder format (<code>#p1=</code>).{' '}
          </span>
          <a href={legacyLinkHref} className="bgp-banner-link">
            Open in Legacy Packet Builder →
          </a>
        </div>
      )}

      {permalinkError && (
        <div className="bgp-banner is-error" role="alert">
          <span>{permalinkError} Loaded the default scenario instead.</span>
          <button
            type="button"
            className="bgp-mini-btn"
            onClick={() => setPermalinkError(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {buildResult.error && (
        <div className="bgp-banner is-error" role="alert">
          <span>Configuration issue: {buildResult.error}</span>
        </div>
      )}

      {showHexDecoder ? (
        <main className="bgp-decoder-main">
          <DecodeBgpHexPanel onClose={() => setShowHexDecoder(false)} />
        </main>
      ) : (
        <main className="bgp-workspace">
          <div className="bgp-col-config">
            <ConfigPanel
              scenarioId={scenarioId}
              config={config}
              events={events}
              onSelectScenario={handleSelectScenario}
              onResetScenario={handleResetScenario}
              onConfigChange={(next) => {
                setConfig(next);
                setPermalinkError(null);
              }}
              onEventsChange={(next) => {
                setEvents(next);
                setPermalinkError(null);
              }}
            />
          </div>

          <div className="bgp-col-ladder">
            <SessionLadder
              routerA={trace.config.routerA}
              routerB={trace.config.routerB}
              steps={trace.steps}
              omissions={trace.omissions}
              notes={trace.notes}
              selectedStepIndex={safeSelectedIndex}
              showTcpSteps={showTcpSteps}
              onToggleTcpSteps={(show) => {
                setShowTcpSteps(show);
                if (!show && selectedStep && selectedStep.kind === 'tcp') {
                  const nextBgp =
                    trace.steps.find((s) => s.index > safeSelectedIndex && s.kind === 'bgp') ??
                    [...trace.steps]
                      .reverse()
                      .find((s) => s.index < safeSelectedIndex && s.kind === 'bgp');
                  if (nextBgp) {
                    setSelectedStepIndex(nextBgp.index);
                  }
                }
              }}
              onSelectStep={setSelectedStepIndex}
            />
          </div>

          <div className="bgp-col-inspector">
            {selectedStep && (
              <BgpMessageInspector
                key={safeSelectedIndex}
                title={selectedStep.summary}
                subtitle={`${selectedStep.from === 'A' ? trace.config.routerA.name : trace.config.routerB.name} → ${selectedStep.to === 'A' ? trace.config.routerA.name : trace.config.routerB.name} · t = ${selectedStep.t}ms · Frame ${selectedStep.frameBytes.length} bytes`}
                bgpBytes={selectedBgpBytes}
                tree={selectedStep.tree}
                explanations={selectedStep.explanations}
                tcpOnlyNote={
                  selectedStep.kind === 'tcp'
                    ? 'TCP transport frame (no BGP payload). Select a BGP arrow on the ladder to inspect its BGP dissection tree.'
                    : undefined
                }
              />
            )}
          </div>

          <div className="bgp-col-state">
            <NegotiatedStatePanel
              routerAName={trace.config.routerA.name}
              routerBName={trace.config.routerB.name}
              state={selectedStep?.state ?? trace.finalState}
            />
          </div>
        </main>
      )}

      <footer className="bgp-footer">
        <span>tsumiki — client-side BGP learning tool (no server, zero telemetry).</span>
        <span className="bgp-footer-links">
          <a
            href="https://github.com/shmuto/packet-builder/issues/new/choose"
            target="_blank"
            rel="noopener noreferrer"
          >
            Report an issue
          </a>
          <span aria-hidden="true">·</span>
          <a href="./legacy/">Legacy Packet Builder</a>
        </span>
      </footer>
    </div>
  );
}
