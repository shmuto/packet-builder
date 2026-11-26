import type { RouteOmission, RouterConfig, SessionStep } from '../../core/session';

export interface SessionLadderProps {
  readonly routerA: RouterConfig;
  readonly routerB: RouterConfig;
  readonly steps: readonly SessionStep[];
  readonly omissions: readonly RouteOmission[];
  readonly notes?: readonly string[];
  readonly selectedStepIndex: number;
  readonly showTcpSteps: boolean;
  readonly onToggleTcpSteps: (show: boolean) => void;
  readonly onSelectStep: (stepIndex: number) => void;
}

function formatRelativeTime(tMs: number): string {
  if (tMs < 1000) return `${tMs}ms`;
  const sec = tMs / 1000;
  return `${sec.toFixed(sec % 1 === 0 ? 0 : 2)}s`;
}

export function SessionLadder({
  routerA,
  routerB,
  steps,
  omissions,
  notes = [],
  selectedStepIndex,
  showTcpSteps,
  onToggleTcpSteps,
  onSelectStep,
}: SessionLadderProps) {
  const visibleSteps = showTcpSteps ? steps : steps.filter((s) => s.kind === 'bgp');

  return (
    <section className="bgp-panel bgp-ladder-panel" aria-label="Session Ladder">
      <div className="bgp-panel-header">
        <h2 className="bgp-panel-title">Session Ladder</h2>
        <label className="bgp-toggle-label">
          <input
            type="checkbox"
            checked={showTcpSteps}
            onChange={(e) => onToggleTcpSteps(e.target.checked)}
          />
          <span>Show TCP steps</span>
        </label>
      </div>

      <div className="bgp-ladder-endpoints" aria-hidden="true">
        <div className="bgp-endpoint-box">
          <strong>{routerA.name}</strong>
          <span className="mono">AS {routerA.asn}</span>
          <span className="mono bgp-endpoint-ip">{routerA.peeringAddress}</span>
        </div>
        <div className="bgp-endpoint-box">
          <strong>{routerB.name}</strong>
          <span className="mono">AS {routerB.asn}</span>
          <span className="mono bgp-endpoint-ip">{routerB.peeringAddress}</span>
        </div>
      </div>

      <div className="bgp-ladder-body" role="listbox" aria-label="BGP session message timeline">
        <div className="bgp-lifeline is-left" aria-hidden="true" />
        <div className="bgp-lifeline is-right" aria-hidden="true" />

        {visibleSteps.map((step) => {
          const isSelected = step.index === selectedStepIndex;
          const dirClass = step.from === 'A' ? 'is-a-to-b' : 'is-b-to-a';
          const msgKind = step.bgpMessage?.type ?? 'tcp';
          return (
            <button
              key={step.index}
              type="button"
              role="option"
              aria-selected={isSelected}
              data-step-index={step.index}
              data-step-kind={step.kind}
              data-bgp-type={step.bgpMessage?.type ?? ''}
              className={`bgp-ladder-step ${dirClass} is-kind-${step.kind} is-msg-${msgKind}${isSelected ? ' is-selected' : ''}`}
              onClick={() => onSelectStep(step.index)}
            >
              <span className="bgp-step-time mono">{formatRelativeTime(step.t)}</span>
              <span className="bgp-step-arrow-track">
                <span className="bgp-step-label">{step.summary}</span>
                <span className="bgp-step-line" aria-hidden="true" />
              </span>
            </button>
          );
        })}
      </div>

      {omissions.length > 0 && (
        <div className="bgp-omissions-box" role="status" aria-label="Unsent Routes">
          <h3 className="bgp-omissions-title">Routes not sent</h3>
          <ul className="bgp-omissions-list">
            {omissions.map((o, idx) => (
              <li key={`${o.router}-${o.prefix}-${idx}`}>
                <strong className="mono">{o.prefix}</strong>: {o.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {notes.length > 0 && (
        <div className="bgp-omissions-box" role="status" aria-label="Session Notes">
          <h3 className="bgp-omissions-title">Session notes</h3>
          <ul className="bgp-omissions-list">
            {notes.map((note, idx) => (
              <li key={idx}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
