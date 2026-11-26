import type {
  BgpLargeCommunity,
  BgpMessage,
  BgpOriginValue,
  DissectionNode,
} from '../bgp';

export type RouterId = 'A' | 'B';
export type SessionType = 'ebgp' | 'ibgp';
export type AddressFamilyId = 'ipv4-unicast' | 'ipv6-unicast';
export type BgpFsmPhase =
  | 'Idle'
  | 'Connect'
  | 'OpenSent'
  | 'OpenConfirm'
  | 'Established'
  | 'Closed';

export interface RouterCapabilities {
  readonly mpIpv4Unicast: boolean;
  readonly mpIpv6Unicast: boolean;
  readonly routeRefresh: boolean;
  readonly fourOctetAs: boolean;
  readonly gracefulRestart: boolean;
}

export interface OriginatedRoute {
  readonly id: string;
  readonly prefix: string;
  readonly origin: BgpOriginValue;
  readonly med?: number;
  readonly localPref?: number;
  readonly communities?: readonly number[];
  readonly largeCommunities?: readonly BgpLargeCommunity[];
}

export interface RouterConfig {
  readonly name: string;
  readonly asn: number;
  /** Optional configured peer ASN; mismatch triggers NOTIFICATION 2/2 (Bad Peer AS). */
  readonly expectedPeerAs?: number;
  readonly routerId: string;
  readonly holdTime: number;
  /** Default LOCAL_PREF for iBGP advertisements (defaults to 100). */
  readonly localPref?: number;
  readonly mac: string;
  /** Peering IP address (IPv4 or IPv6). Both routers must use the same IP version. */
  readonly peeringAddress: string;
  /** Optional IPv4 next hop used when advertising IPv4 routes over an IPv6 peering session. */
  readonly ipv4NextHop?: string;
  /** Optional IPv6 next hop used when advertising IPv6 routes over an IPv4 peering session. */
  readonly ipv6NextHop?: string;
  readonly capabilities: RouterCapabilities;
  readonly routes: readonly OriginatedRoute[];
}

export interface SessionConfig {
  readonly routerA: RouterConfig;
  readonly routerB: RouterConfig;
  /** Base Unix epoch timestamp in milliseconds for synthetic pcap timestamps. */
  readonly baseTimestampMs?: number;
}

export type SessionEvent =
  | { readonly type: 'establish' }
  | {
      readonly type: 'advertise';
      readonly router: RouterId;
      readonly routeIds?: readonly string[];
      readonly prefixes?: readonly string[];
    }
  | {
      readonly type: 'withdraw';
      readonly router: RouterId;
      readonly routeIds?: readonly string[];
      readonly prefixes?: readonly string[];
    }
  | { readonly type: 'endOfRib'; readonly router?: RouterId }
  | { readonly type: 'holdTimerExpires'; readonly router: RouterId }
  | { readonly type: 'adminShutdown'; readonly router: RouterId };

export type CapabilityKey = keyof RouterCapabilities;

export interface CapabilityNegotiationEntry {
  readonly key: CapabilityKey;
  readonly label: string;
  readonly advertisedByA: boolean;
  readonly advertisedByB: boolean;
  readonly active: boolean;
  readonly reference: string;
}

export interface NegotiatedState {
  readonly phase: BgpFsmPhase;
  readonly sessionType: SessionType;
  readonly negotiatedHoldTime: number | null;
  readonly keepaliveInterval: number | null;
  readonly capabilities: readonly CapabilityNegotiationEntry[];
  readonly activeFamilies: readonly AddressFamilyId[];
  readonly fourOctetAsActive: boolean;
  readonly closedReason?: string;
}

export interface SessionStep {
  readonly index: number;
  /** Milliseconds since the start of the session. */
  readonly t: number;
  /** Absolute synthetic Unix timestamp in milliseconds for pcap export. */
  readonly timestampMs: number;
  readonly from: RouterId;
  readonly to: RouterId;
  readonly kind: 'tcp' | 'bgp';
  readonly summary: string;
  readonly frameBytes: Uint8Array;
  /** Byte offset of the BGP message inside frameBytes (undefined for TCP-only frames). */
  readonly bgpOffset?: number;
  readonly bgpMessage?: BgpMessage;
  readonly tree?: DissectionNode;
  readonly explanations: readonly string[];
  readonly state: NegotiatedState;
}

export interface RouteOmission {
  readonly router: RouterId;
  readonly prefix: string;
  readonly reason: string;
  readonly reference: string;
}

export interface SessionTrace {
  readonly config: SessionConfig;
  readonly events: readonly SessionEvent[];
  readonly steps: readonly SessionStep[];
  readonly omissions: readonly RouteOmission[];
  readonly notes: readonly string[];
  readonly finalState: NegotiatedState;
}

export interface SessionScenario {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly config: SessionConfig;
  readonly events: readonly SessionEvent[];
}
