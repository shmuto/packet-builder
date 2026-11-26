import type { NegotiatedState } from '../../core/session';

export interface NegotiatedStatePanelProps {
  readonly routerAName: string;
  readonly routerBName: string;
  readonly state: NegotiatedState;
}

export function NegotiatedStatePanel({
  routerAName,
  routerBName,
  state,
}: NegotiatedStatePanelProps) {
  return (
    <section className="bgp-panel bgp-state-panel" aria-label="Negotiated Session State">
      <div className="bgp-panel-header">
        <h2 className="bgp-panel-title">Negotiated State</h2>
        <span className={`bgp-session-badge is-${state.sessionType}`}>
          {state.sessionType === 'ebgp' ? 'eBGP' : 'iBGP'}
        </span>
      </div>

      <dl className="bgp-state-grid">
        <div className="bgp-state-kv">
          <dt>FSM State</dt>
          <dd className="mono">{state.phase}</dd>
        </div>
        <div className="bgp-state-kv">
          <dt>Hold Time</dt>
          <dd className="mono">
            {state.negotiatedHoldTime === null
              ? 'Not negotiated'
              : state.negotiatedHoldTime === 0
                ? '0 s (disabled)'
                : `${state.negotiatedHoldTime} s`}
          </dd>
        </div>
        <div className="bgp-state-kv">
          <dt>KEEPALIVE Interval</dt>
          <dd className="mono">
            {state.keepaliveInterval === null
              ? 'Not negotiated'
              : state.keepaliveInterval === 0
                ? 'None (Hold = 0)'
                : `${state.keepaliveInterval} s`}
          </dd>
        </div>
        <div className="bgp-state-kv">
          <dt>Active Families</dt>
          <dd className="mono">
            {state.activeFamilies.length > 0 ? state.activeFamilies.join(', ') : 'None yet'}
          </dd>
        </div>
      </dl>

      {state.closedReason && (
        <p className="bgp-closed-reason" role="status">
          Closed: {state.closedReason}
        </p>
      )}

      <div className="bgp-cap-table-wrap">
        <table className="bgp-cap-table">
          <thead>
            <tr>
              <th>Capability</th>
              <th>{routerAName}</th>
              <th>{routerBName}</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {state.capabilities.map((cap) => (
              <tr key={cap.key}>
                <td>
                  <span className="bgp-cap-name">{cap.label}</span>{' '}
                  <span className="bgp-tree-ref mono">{cap.reference}</span>
                </td>
                <td className="mono">{cap.advertisedByA ? 'Yes' : '—'}</td>
                <td className="mono">{cap.advertisedByB ? 'Yes' : '—'}</td>
                <td>
                  <span className={`bgp-cap-status${cap.active ? ' is-active' : ''}`}>
                    {cap.active ? 'Active' : 'Inactive'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
