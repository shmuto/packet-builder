export const BGP_HEADER_LENGTH = 19;
export const BGP_MARKER_LENGTH = 16;
export const BGP_MAX_MESSAGE_LENGTH = 4096;
export const BGP_DEFAULT_VERSION = 4;
export const BGP_AS_TRANS = 23456;

export const BGP_MESSAGE_TYPE = {
  OPEN: 1,
  UPDATE: 2,
  NOTIFICATION: 3,
  KEEPALIVE: 4,
  ROUTE_REFRESH: 5,
} as const;

export type BgpMessageTypeCode = (typeof BGP_MESSAGE_TYPE)[keyof typeof BGP_MESSAGE_TYPE];

export const BGP_AFI = {
  IPV4: 1,
  IPV6: 2,
} as const;

export const BGP_SAFI = {
  UNICAST: 1,
  MULTICAST: 2,
} as const;

export const BGP_CAPABILITY_CODE = {
  MULTIPROTOCOL: 1,
  ROUTE_REFRESH: 2,
  GRACEFUL_RESTART: 64,
  FOUR_OCTET_AS: 65,
  ADD_PATH: 69,
  ENHANCED_ROUTE_REFRESH: 70,
} as const;

export const BGP_ATTR_TYPE = {
  ORIGIN: 1,
  AS_PATH: 2,
  NEXT_HOP: 3,
  MULTI_EXIT_DISC: 4,
  LOCAL_PREF: 5,
  ATOMIC_AGGREGATE: 6,
  AGGREGATOR: 7,
  COMMUNITIES: 8,
  MP_REACH_NLRI: 14,
  MP_UNREACH_NLRI: 15,
  AS4_PATH: 17,
  AS4_AGGREGATOR: 18,
  LARGE_COMMUNITY: 32,
} as const;

export const BGP_ORIGIN = {
  IGP: 0,
  EGP: 1,
  INCOMPLETE: 2,
} as const;

export type BgpOriginValue = 0 | 1 | 2;

export const BGP_AS_PATH_SEGMENT_TYPE = {
  AS_SET: 1,
  AS_SEQUENCE: 2,
} as const;

export type BgpAsPathSegmentType = 1 | 2;

export const BGP_ADD_PATH_MODE = {
  RECEIVE: 1,
  SEND: 2,
  SEND_RECEIVE: 3,
} as const;

export type BgpAddPathMode = 1 | 2 | 3;

export const BGP_ROUTE_REFRESH_SUBTYPE = {
  NORMAL: 0,
  BORR: 1,
  EORR: 2,
} as const;

export interface AfiSafi {
  readonly afi: number;
  readonly safi: number;
}

export function afiSafiKey(afi: number, safi: number): string {
  return `${afi}:${safi}`;
}

export interface BgpCodecContext {
  /**
   * Whether 4-octet AS numbers (RFC 6793) are negotiated for this session.
   * When true, AS_PATH and AGGREGATOR encode ASNs as 4 bytes; when false, 2 bytes.
   */
  readonly fourOctetAs: boolean;
  /**
   * Address families for which ADD-PATH (RFC 7911) is active.
   * Accepts either a Set of `"<afi>:<safi>"` keys (via `afiSafiKey`) or an array of `{ afi, safi }`.
   */
  readonly addPath?: ReadonlySet<string> | readonly AfiSafi[];
}

export const DEFAULT_BGP_CODEC_CONTEXT: BgpCodecContext = {
  fourOctetAs: true,
};

export function hasAddPathForAfiSafi(
  ctx: BgpCodecContext,
  afi: number,
  safi: number,
): boolean {
  const addPath = ctx.addPath;
  if (!addPath) return false;
  if (addPath instanceof Set) {
    return addPath.has(afiSafiKey(afi, safi));
  }
  return (addPath as readonly AfiSafi[]).some(
    (entry) => entry.afi === afi && entry.safi === safi,
  );
}

// ---------------------------------------------------------------------------
// Dissection Tree
// ---------------------------------------------------------------------------

export interface ByteRange {
  /** Inclusive start byte offset relative to the start of the BGP message. */
  readonly start: number;
  /** Exclusive end byte offset (`end >= start`). */
  readonly end: number;
}

export interface DissectionNode {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly explanation: string;
  readonly reference: string;
  readonly byteRange: ByteRange;
  readonly children?: readonly DissectionNode[];
}

// ---------------------------------------------------------------------------
// OPEN Capabilities (RFC 5492)
// ---------------------------------------------------------------------------

export interface BgpMultiprotocolCapability {
  readonly kind: 'mp';
  readonly afi: number;
  readonly safi: number;
  readonly reserved?: number;
}

export interface BgpRouteRefreshCapability {
  readonly kind: 'routeRefresh';
}

export interface BgpGracefulRestartTuple {
  readonly afi: number;
  readonly safi: number;
  readonly forwardingState: boolean;
  /** Low 7 bits of flags byte (usually 0). */
  readonly reservedFlags?: number;
}

export interface BgpGracefulRestartCapability {
  readonly kind: 'gracefulRestart';
  /** 4-bit Restart Flags (bit 0x8 = R-bit Restart State, bit 0x4 = N-bit Notification). */
  readonly restartFlags: number;
  /** 12-bit Restart Time in seconds (0..4095). */
  readonly restartTime: number;
  readonly tuples: readonly BgpGracefulRestartTuple[];
}

export interface BgpFourOctetAsCapability {
  readonly kind: 'fourOctetAs';
  readonly asn: number;
}

export interface BgpAddPathEntry {
  readonly afi: number;
  readonly safi: number;
  readonly sendReceive: BgpAddPathMode;
}

export interface BgpAddPathCapability {
  readonly kind: 'addPath';
  readonly entries: readonly BgpAddPathEntry[];
}

export interface BgpEnhancedRouteRefreshCapability {
  readonly kind: 'enhancedRouteRefresh';
}

export interface BgpRawCapability {
  readonly kind: 'raw';
  readonly code: number;
  readonly dataHex: string;
}

export type BgpCapability =
  | BgpMultiprotocolCapability
  | BgpRouteRefreshCapability
  | BgpGracefulRestartCapability
  | BgpFourOctetAsCapability
  | BgpAddPathCapability
  | BgpEnhancedRouteRefreshCapability
  | BgpRawCapability;

export interface BgpRawOptionalParameter {
  readonly type: number;
  readonly dataHex: string;
  readonly lengthOverride?: number;
}

// ---------------------------------------------------------------------------
// Prefixes & Path Attributes
// ---------------------------------------------------------------------------

export interface BgpPrefix {
  /** CIDR notation, e.g. `"203.0.113.0/24"` or `"2001:db8::/32"`. */
  readonly prefix: string;
  /** 32-bit ADD-PATH Path Identifier (RFC 7911 §3), encoded when ADD-PATH is active. */
  readonly pathId?: number;
}

export interface BgpAttrFlags {
  readonly optional: boolean;
  readonly transitive: boolean;
  readonly partial: boolean;
  readonly extendedLength: boolean;
}

export interface BgpAttrFlagsOverride {
  readonly optional?: boolean;
  readonly transitive?: boolean;
  readonly partial?: boolean;
  readonly extendedLength?: boolean;
  /** Raw low 4 unused bits (normally 0). */
  readonly unusedBits?: number;
}

interface BgpPathAttributeBase {
  readonly flags?: BgpAttrFlagsOverride;
  readonly lengthOverride?: number;
}

export interface BgpOriginAttribute extends BgpPathAttributeBase {
  readonly kind: 'origin';
  readonly origin: BgpOriginValue;
}

export interface BgpAsPathSegment {
  readonly type: BgpAsPathSegmentType;
  readonly asns: readonly number[];
}

export interface BgpAsPathAttribute extends BgpPathAttributeBase {
  readonly kind: 'asPath';
  readonly segments: readonly BgpAsPathSegment[];
}

export interface BgpNextHopAttribute extends BgpPathAttributeBase {
  readonly kind: 'nextHop';
  readonly nextHop: string;
}

export interface BgpMedAttribute extends BgpPathAttributeBase {
  readonly kind: 'med';
  readonly med: number;
}

export interface BgpLocalPrefAttribute extends BgpPathAttributeBase {
  readonly kind: 'localPref';
  readonly localPref: number;
}

export interface BgpAtomicAggregateAttribute extends BgpPathAttributeBase {
  readonly kind: 'atomicAggregate';
}

export interface BgpAggregatorAttribute extends BgpPathAttributeBase {
  readonly kind: 'aggregator';
  readonly asn: number;
  readonly ipAddress: string;
}

export interface BgpCommunitiesAttribute extends BgpPathAttributeBase {
  readonly kind: 'communities';
  /** 32-bit RFC 1997 community values (high 16 bits = ASN, low 16 bits = local value). */
  readonly communities: readonly number[];
}

export interface BgpMpReachNlriAttribute extends BgpPathAttributeBase {
  readonly kind: 'mpReachNlri';
  readonly afi: number;
  readonly safi: number;
  /** Next-hop IPv6 (1 or 2 addresses) or IPv4 addresses; ignored if `nextHopRawHex` is provided. */
  readonly nextHops: readonly string[];
  /** Optional raw hex next hop for non-IPv4/IPv6 AFIs or non-standard lengths. */
  readonly nextHopRawHex?: string;
  readonly reserved?: number;
  readonly nlri: readonly BgpPrefix[];
}

export interface BgpMpUnreachNlriAttribute extends BgpPathAttributeBase {
  readonly kind: 'mpUnreachNlri';
  readonly afi: number;
  readonly safi: number;
  readonly withdrawnRoutes: readonly BgpPrefix[];
}

export interface BgpAs4PathAttribute extends BgpPathAttributeBase {
  readonly kind: 'as4Path';
  readonly segments: readonly BgpAsPathSegment[];
}

export interface BgpAs4AggregatorAttribute extends BgpPathAttributeBase {
  readonly kind: 'as4Aggregator';
  readonly asn: number;
  readonly ipAddress: string;
}

export interface BgpLargeCommunity {
  readonly globalAdmin: number;
  readonly localData1: number;
  readonly localData2: number;
}

export interface BgpLargeCommunitiesAttribute extends BgpPathAttributeBase {
  readonly kind: 'largeCommunities';
  readonly communities: readonly BgpLargeCommunity[];
}

export interface BgpRawAttribute extends BgpPathAttributeBase {
  readonly kind: 'raw';
  readonly typeCode: number;
  readonly dataHex: string;
}

export type BgpPathAttribute =
  | BgpOriginAttribute
  | BgpAsPathAttribute
  | BgpNextHopAttribute
  | BgpMedAttribute
  | BgpLocalPrefAttribute
  | BgpAtomicAggregateAttribute
  | BgpAggregatorAttribute
  | BgpCommunitiesAttribute
  | BgpMpReachNlriAttribute
  | BgpMpUnreachNlriAttribute
  | BgpAs4PathAttribute
  | BgpAs4AggregatorAttribute
  | BgpLargeCommunitiesAttribute
  | BgpRawAttribute;

// ---------------------------------------------------------------------------
// BGP Messages (RFC 4271 §4 + RFC 2918)
// ---------------------------------------------------------------------------

interface BgpMessageBase {
  /** Optional 16-byte Marker override in hex; defaults to 16 bytes of 0xff (RFC 4271 §4.1). */
  readonly markerHex?: string;
  /** Optional manual override for the 16-bit Message Length header field. */
  readonly lengthOverride?: number;
}

export interface BgpOpenMessage extends BgpMessageBase {
  readonly type: 'open';
  readonly version: number;
  /**
   * Speaker's ASN (1..4294967295). My AS header field is automatically filled with
   * `asn` if `asn <= 65535`, otherwise `AS_TRANS` (23456) per RFC 6793 §3.
   */
  readonly asn: number;
  /** Optional manual override for the 16-bit My Autonomous System header field. */
  readonly myAsOverride?: number;
  readonly holdTime: number;
  readonly bgpIdentifier: string;
  readonly capabilities: readonly BgpCapability[];
  /** Optional non-Capabilities (type != 2) optional parameters preserved on decode/encode. */
  readonly extraOptionalParameters?: readonly BgpRawOptionalParameter[];
  /** Optional manual override for the 8-bit Optional Parameters Length field. */
  readonly optParamLengthOverride?: number;
  /** Optional manual override for the Capabilities Optional Parameter (type 2) length field. */
  readonly capParamLengthOverride?: number;
}

export interface BgpUpdateMessage extends BgpMessageBase {
  readonly type: 'update';
  readonly withdrawnRoutes: readonly BgpPrefix[];
  readonly pathAttributes: readonly BgpPathAttribute[];
  readonly nlri: readonly BgpPrefix[];
  /** Optional manual override for the 16-bit Withdrawn Routes Length field. */
  readonly withdrawnRoutesLengthOverride?: number;
  /** Optional manual override for the 16-bit Total Path Attribute Length field. */
  readonly totalPathAttributeLengthOverride?: number;
}

export interface BgpNotificationMessage extends BgpMessageBase {
  readonly type: 'notification';
  readonly errorCode: number;
  readonly errorSubcode: number;
  readonly dataHex: string;
}

export interface BgpKeepaliveMessage extends BgpMessageBase {
  readonly type: 'keepalive';
}

export interface BgpRouteRefreshMessage extends BgpMessageBase {
  readonly type: 'routeRefresh';
  readonly afi: number;
  /** Reserved byte in RFC 2918 (0 = Normal), or Subtype in RFC 7313 (1 = BoRR, 2 = EoRR). */
  readonly subtype: number;
  readonly safi: number;
}

export interface BgpUnknownMessage extends BgpMessageBase {
  readonly type: 'unknown';
  readonly typeCode: number;
  readonly bodyHex: string;
}

export type BgpMessage =
  | BgpOpenMessage
  | BgpUpdateMessage
  | BgpNotificationMessage
  | BgpKeepaliveMessage
  | BgpRouteRefreshMessage
  | BgpUnknownMessage;

export interface EncodedBgpMessage {
  readonly bytes: Uint8Array;
  readonly tree: DissectionNode;
  readonly warnings: readonly string[];
}

export interface DecodedBgpMessage {
  readonly message: BgpMessage;
  readonly bytes: Uint8Array;
  readonly tree: DissectionNode;
  readonly offset: number;
  readonly notes: readonly string[];
}

export interface BgpDecodeResult {
  readonly messages: readonly DecodedBgpMessage[];
  readonly notes: readonly string[];
  readonly unparsedBytes: Uint8Array;
  readonly unparsedOffset: number;
}
