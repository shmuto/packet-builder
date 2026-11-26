import { useEffect, useState } from 'react';
import { formatCommunity, makeCommunity, type BgpOriginValue } from '../../core/bgp';
import {
  BUILTIN_SCENARIOS,
  MAX_SESSION_EVENTS,
  MAX_SESSION_ROUTES,
  type CapabilityKey,
  type OriginatedRoute,
  type RouterConfig,
  type RouterId,
  type SessionConfig,
  type SessionEvent,
} from '../../core/session';

export interface ConfigPanelProps {
  readonly scenarioId: string;
  readonly config: SessionConfig;
  readonly events: readonly SessionEvent[];
  readonly onSelectScenario: (id: string) => void;
  readonly onResetScenario: () => void;
  readonly onConfigChange: (next: SessionConfig) => void;
  readonly onEventsChange: (next: readonly SessionEvent[]) => void;
}

const CAPABILITY_LABELS: readonly { readonly key: CapabilityKey; readonly label: string }[] = [
  { key: 'mpIpv4Unicast', label: 'MP IPv4 Unicast' },
  { key: 'mpIpv6Unicast', label: 'MP IPv6 Unicast' },
  { key: 'routeRefresh', label: 'Route Refresh' },
  { key: 'fourOctetAs', label: '4-octet AS' },
  { key: 'gracefulRestart', label: 'Graceful Restart' },
];

const COMMUNITY_TOKEN_PATTERN = /^(\d+):(\d+)$/;

function parseCommunitiesText(text: string): {
  readonly values: readonly number[];
  readonly invalidTokens: readonly string[];
} {
  const parts = text
    .split(/[,\s]+/)
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  const values: number[] = [];
  const invalidTokens: string[] = [];
  for (const part of parts) {
    const match = COMMUNITY_TOKEN_PATTERN.exec(part);
    if (!match) {
      invalidTokens.push(part);
      continue;
    }
    const hi = Number.parseInt(match[1], 10);
    const lo = Number.parseInt(match[2], 10);
    if (
      Number.isInteger(hi) &&
      hi >= 0 &&
      hi <= 65535 &&
      Number.isInteger(lo) &&
      lo >= 0 &&
      lo <= 65535
    ) {
      values.push(makeCommunity(hi, lo));
    } else {
      invalidTokens.push(part);
    }
  }
  return { values, invalidTokens };
}

function formatCommunitiesInput(communities?: readonly number[]): string {
  if (!communities || communities.length === 0) return '';
  return communities
    .map((c) => {
      const hi = (c >>> 16) & 0xffff;
      const lo = c & 0xffff;
      return `${hi}:${lo}`;
    })
    .join(', ');
}

function describeEvent(ev: SessionEvent, config: SessionConfig): string {
  const routerName = (id: RouterId) => (id === 'A' ? config.routerA.name : config.routerB.name);
  switch (ev.type) {
    case 'establish':
      return 'Establish TCP + BGP OPEN / KEEPALIVE';
    case 'advertise':
      return `${routerName(ev.router)}: Advertise ${ev.prefixes?.join(', ') ?? ev.routeIds?.join(', ') ?? 'all routes'}`;
    case 'withdraw':
      return `${routerName(ev.router)}: Withdraw ${ev.prefixes?.join(', ') ?? ev.routeIds?.join(', ') ?? 'all routes'}`;
    case 'endOfRib':
      return `${ev.router ? routerName(ev.router) : 'Both'}: Send End-of-RIB`;
    case 'holdTimerExpires':
      return `${routerName(ev.router)}: Hold Timer Expires (NOTIFICATION 4/0)`;
    case 'adminShutdown':
      return `${routerName(ev.router)}: Admin Shutdown (NOTIFICATION 6/2)`;
  }
}

interface RouteItemEditorProps {
  readonly sideLabel: string;
  readonly index: number;
  readonly route: OriginatedRoute;
  readonly onChange: (nextRoute: OriginatedRoute) => void;
  readonly onRemove: () => void;
}

function RouteItemEditor({ sideLabel, index, route, onChange, onRemove }: RouteItemEditorProps) {
  const formattedCommunities = formatCommunitiesInput(route.communities);
  const [communitiesText, setCommunitiesText] = useState(formattedCommunities);
  const [communitiesError, setCommunitiesError] = useState<string | null>(null);

  useEffect(() => {
    setCommunitiesText(formattedCommunities);
    setCommunitiesError(null);
  }, [formattedCommunities]);

  const commitCommunities = (raw: string) => {
    const { values, invalidTokens } = parseCommunitiesText(raw);
    if (invalidTokens.length > 0) {
      setCommunitiesError(
        `Invalid community ${invalidTokens.map((t) => `"${t}"`).join(', ')} (expected ASN:VALUE, each 0–65535).`,
      );
      return;
    }
    setCommunitiesError(null);
    if (values.length === 0) {
      const { communities: _c, ...rest } = route;
      onChange(rest);
    } else {
      onChange({ ...route, communities: values });
    }
  };

  return (
    <div className="bgp-route-item">
      <div className="bgp-route-row">
        <input
          type="text"
          className="mono bgp-route-prefix"
          aria-label={`${sideLabel} Route ${index + 1} Prefix`}
          value={route.prefix}
          onChange={(e) => onChange({ ...route, prefix: e.target.value.trim() })}
        />
        <select
          aria-label={`${sideLabel} Route ${index + 1} Origin`}
          value={route.origin}
          onChange={(e) =>
            onChange({
              ...route,
              origin: Number(e.target.value) as BgpOriginValue,
            })
          }
        >
          <option value={0}>IGP</option>
          <option value={1}>EGP</option>
          <option value={2}>INCOMPLETE</option>
        </select>
        <button
          type="button"
          className="icon-btn is-danger"
          aria-label={`Remove ${sideLabel} route ${route.prefix}`}
          onClick={onRemove}
        >
          ✕
        </button>
      </div>
      <div className="bgp-route-meta-row">
        <label className="bgp-inline-field">
          <span>MED</span>
          <input
            type="number"
            min={0}
            max={4294967295}
            placeholder="—"
            aria-label={`${sideLabel} Route ${index + 1} MED`}
            value={route.med ?? ''}
            onChange={(e) => {
              if (e.target.value.trim() === '') {
                const { med: _m, ...rest } = route;
                onChange(rest);
                return;
              }
              const val = Number.parseInt(e.target.value, 10);
              if (Number.isInteger(val) && val >= 0 && val <= 0xffffffff) {
                onChange({ ...route, med: val });
              }
            }}
          />
        </label>
        <label className="bgp-inline-field is-grow">
          <span>Communities</span>
          <input
            type="text"
            className="mono"
            placeholder="65001:100"
            aria-label={`${sideLabel} Route ${index + 1} Communities`}
            value={communitiesText}
            onChange={(e) => {
              setCommunitiesText(e.target.value);
              if (communitiesError) setCommunitiesError(null);
            }}
            onBlur={() => commitCommunities(communitiesText)}
          />
        </label>
      </div>
      {communitiesError && (
        <div className="bgp-inline-error" role="alert">
          {communitiesError}
        </div>
      )}
      {route.communities && route.communities.length > 0 && (
        <div className="bgp-community-preview mono">
          {route.communities.map((c) => formatCommunity(c)).join(', ')}
        </div>
      )}
    </div>
  );
}

function pickUniqueRoutePrefix(
  side: RouterId,
  family: 'ipv4' | 'ipv6',
  existing: readonly OriginatedRoute[],
): string {
  const existingSet = new Set(existing.map((r) => r.prefix));
  if (family === 'ipv4') {
    const baseThirdOctet = side === 'A' ? 113 : 100;
    const prefixHead = side === 'A' ? '203.0' : '198.51';
    for (let offset = 0; offset < 256; offset++) {
      const third = (baseThirdOctet + offset) % 256;
      const candidate = `${prefixHead}.${third}.0/24`;
      if (!existingSet.has(candidate)) {
        return candidate;
      }
    }
    return `${prefixHead}.${baseThirdOctet}.0/24`;
  }

  const baseHextet = side === 'A' ? 1 : 17;
  for (let offset = 0; offset < 256; offset++) {
    const hextet = (baseHextet + offset).toString(16);
    const candidate = `2001:db8:${hextet}::/48`;
    if (!existingSet.has(candidate)) {
      return candidate;
    }
  }
  return `2001:db8:${baseHextet.toString(16)}::/48`;
}

interface RouterEditorCardProps {
  readonly side: RouterId;
  readonly router: RouterConfig;
  readonly onChange: (next: RouterConfig) => void;
}

function RouterEditorCard({ side, router, onChange }: RouterEditorCardProps) {
  const sideLabel = `Router ${side}`;
  const routesAtLimit = router.routes.length >= MAX_SESSION_ROUTES;

  const updateRoute = (idx: number, nextRoute: OriginatedRoute) => {
    const copy = router.routes.slice();
    copy[idx] = nextRoute;
    onChange({ ...router, routes: copy });
  };

  const removeRoute = (idx: number) => {
    onChange({ ...router, routes: router.routes.filter((_, i) => i !== idx) });
  };

  const addRoute = (family: 'ipv4' | 'ipv6') => {
    if (router.routes.length >= MAX_SESSION_ROUTES) return;
    const prefix = pickUniqueRoutePrefix(side, family, router.routes);
    const newRoute: OriginatedRoute = {
      id: `r-${side.toLowerCase()}-${family}-${Date.now()}-${router.routes.length + 1}`,
      prefix,
      origin: 0,
    };
    onChange({ ...router, routes: [...router.routes, newRoute] });
  };

  return (
    <details className="bgp-router-card" open>
      <summary className="bgp-router-summary">
        <span>
          {sideLabel} ({router.name})
        </span>
        <span className="mono bgp-router-summary-meta">
          AS {router.asn} · {router.peeringAddress}
        </span>
      </summary>

      <div className="bgp-router-body">
        <div className="bgp-form-grid">
          <label className="bgp-field">
            <span className="bgp-field-label">ASN</span>
            <input
              type="number"
              min={1}
              max={4294967295}
              aria-label={`${sideLabel} ASN`}
              value={router.asn}
              onChange={(e) => {
                const parsed = Number.parseInt(e.target.value, 10);
                if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 0xffffffff) {
                  onChange({ ...router, asn: parsed });
                }
              }}
            />
          </label>

          <label className="bgp-field">
            <span className="bgp-field-label">Router ID</span>
            <input
              type="text"
              aria-label={`${sideLabel} Router ID`}
              value={router.routerId}
              onChange={(e) => onChange({ ...router, routerId: e.target.value.trim() })}
            />
          </label>

          <label className="bgp-field">
            <span className="bgp-field-label">Hold Time (s)</span>
            <input
              type="number"
              min={0}
              max={65535}
              aria-label={`${sideLabel} Hold Time`}
              value={router.holdTime}
              onChange={(e) => {
                const parsed = Number.parseInt(e.target.value, 10);
                if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 65535) {
                  onChange({ ...router, holdTime: parsed });
                }
              }}
            />
          </label>

          <label className="bgp-field">
            <span className="bgp-field-label">Expected Peer AS</span>
            <input
              type="number"
              min={1}
              max={4294967295}
              placeholder="(match peer)"
              aria-label={`${sideLabel} Expected Peer AS`}
              value={router.expectedPeerAs ?? ''}
              onChange={(e) => {
                if (e.target.value.trim() === '') {
                  const { expectedPeerAs: _removed, ...rest } = router;
                  onChange(rest);
                  return;
                }
                const parsed = Number.parseInt(e.target.value, 10);
                if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 0xffffffff) {
                  onChange({ ...router, expectedPeerAs: parsed });
                }
              }}
            />
          </label>
        </div>

        <fieldset className="bgp-cap-fieldset">
          <legend className="bgp-field-label">Capabilities</legend>
          <div className="bgp-cap-checks">
            {CAPABILITY_LABELS.map(({ key, label }) => (
              <label key={key} className="bgp-check-chip">
                <input
                  type="checkbox"
                  aria-label={`${sideLabel} ${label}`}
                  checked={router.capabilities[key]}
                  onChange={(e) =>
                    onChange({
                      ...router,
                      capabilities: {
                        ...router.capabilities,
                        [key]: e.target.checked,
                      },
                    })
                  }
                />
                <span>{label}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="bgp-routes-section">
          <div className="bgp-routes-header">
            <span className="bgp-field-label">
              Originated Routes ({router.routes.length}/{MAX_SESSION_ROUTES})
            </span>
            <div className="bgp-routes-add-btns">
              <button
                type="button"
                className="bgp-mini-btn"
                aria-label={`${sideLabel} Add IPv4 Route`}
                disabled={routesAtLimit}
                onClick={() => addRoute('ipv4')}
              >
                + IPv4
              </button>
              <button
                type="button"
                className="bgp-mini-btn"
                aria-label={`${sideLabel} Add IPv6 Route`}
                disabled={routesAtLimit}
                onClick={() => addRoute('ipv6')}
              >
                + IPv6
              </button>
            </div>
          </div>

          {router.routes.length === 0 ? (
            <p className="bgp-empty-hint">No originated routes.</p>
          ) : (
            <div className="bgp-route-list">
              {router.routes.map((route, idx) => (
                <RouteItemEditor
                  key={route.id}
                  sideLabel={sideLabel}
                  index={idx}
                  route={route}
                  onChange={(nextRoute) => updateRoute(idx, nextRoute)}
                  onRemove={() => removeRoute(idx)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </details>
  );
}

export function ConfigPanel({
  scenarioId,
  config,
  events,
  onSelectScenario,
  onResetScenario,
  onConfigChange,
  onEventsChange,
}: ConfigPanelProps) {
  const [newEventType, setNewEventType] = useState<
    'advertise' | 'withdraw' | 'endOfRib' | 'holdTimerExpires' | 'adminShutdown'
  >('advertise');
  const [newEventRouter, setNewEventRouter] = useState<RouterId>('A');
  const eventsAtLimit = events.length >= MAX_SESSION_EVENTS;

  const moveEvent = (idx: number, delta: -1 | 1) => {
    const target = idx + delta;
    if (target < 1 || target >= events.length) return; // keep establish at index 0
    const copy = events.slice();
    const [item] = copy.splice(idx, 1);
    copy.splice(target, 0, item);
    onEventsChange(copy);
  };

  const removeEvent = (idx: number) => {
    if (idx === 0 && events[0]?.type === 'establish') return;
    onEventsChange(events.filter((_, i) => i !== idx));
  };

  const addEvent = () => {
    if (events.length >= MAX_SESSION_EVENTS) return;
    const ev: SessionEvent =
      newEventType === 'endOfRib'
        ? { type: 'endOfRib', router: newEventRouter }
        : { type: newEventType, router: newEventRouter };
    onEventsChange([...events, ev]);
  };

  return (
    <aside className="bgp-panel bgp-config-panel" aria-label="Session Configuration">
      <div className="bgp-panel-header">
        <h2 className="bgp-panel-title">Session Config</h2>
        <button type="button" className="bgp-mini-btn" onClick={onResetScenario}>
          Reset
        </button>
      </div>

      <label className="bgp-field">
        <span className="bgp-field-label">Scenario</span>
        <select
          aria-label="Scenario"
          value={scenarioId}
          onChange={(e) => onSelectScenario(e.target.value)}
        >
          {BUILTIN_SCENARIOS.map((sc) => (
            <option key={sc.id} value={sc.id}>
              {sc.title} ({sc.id})
            </option>
          ))}
        </select>
      </label>

      <RouterEditorCard
        side="A"
        router={config.routerA}
        onChange={(routerA) => onConfigChange({ ...config, routerA })}
      />

      <RouterEditorCard
        side="B"
        router={config.routerB}
        onChange={(routerB) => onConfigChange({ ...config, routerB })}
      />

      <details className="bgp-router-card" open>
        <summary className="bgp-router-summary">
          <span>
            Session Events ({events.length}/{MAX_SESSION_EVENTS})
          </span>
        </summary>
        <div className="bgp-router-body">
          <ol className="bgp-event-list">
            {events.map((ev, idx) => (
              <li key={idx} className="bgp-event-item">
                <span className="bgp-event-text">{describeEvent(ev, config)}</span>
                <span className="bgp-event-actions">
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label={`Move event ${idx + 1} up`}
                    disabled={idx <= 1}
                    onClick={() => moveEvent(idx, -1)}
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label={`Move event ${idx + 1} down`}
                    disabled={idx === 0 || idx === events.length - 1}
                    onClick={() => moveEvent(idx, 1)}
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    className="icon-btn is-danger"
                    aria-label={`Remove event ${idx + 1}`}
                    disabled={idx === 0 && ev.type === 'establish'}
                    onClick={() => removeEvent(idx)}
                  >
                    ✕
                  </button>
                </span>
              </li>
            ))}
          </ol>

          <div className="bgp-event-add-bar">
            <select
              aria-label="Event type to add"
              value={newEventType}
              onChange={(e) =>
                setNewEventType(
                  e.target.value as
                    | 'advertise'
                    | 'withdraw'
                    | 'endOfRib'
                    | 'holdTimerExpires'
                    | 'adminShutdown',
                )
              }
            >
              <option value="advertise">Advertise routes</option>
              <option value="withdraw">Withdraw routes</option>
              <option value="endOfRib">Send End-of-RIB</option>
              <option value="holdTimerExpires">Hold Timer Expires</option>
              <option value="adminShutdown">Admin Shutdown</option>
            </select>
            <select
              aria-label="Event router"
              value={newEventRouter}
              onChange={(e) => setNewEventRouter(e.target.value as RouterId)}
            >
              <option value="A">{config.routerA.name} (A)</option>
              <option value="B">{config.routerB.name} (B)</option>
            </select>
            <button
              type="button"
              className="bgp-mini-btn"
              disabled={eventsAtLimit}
              onClick={addEvent}
            >
              + Add Event
            </button>
          </div>
        </div>
      </details>
    </aside>
  );
}
