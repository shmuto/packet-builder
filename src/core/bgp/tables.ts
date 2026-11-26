import {
  BGP_AFI,
  BGP_ATTR_TYPE,
  BGP_CAPABILITY_CODE,
  BGP_MESSAGE_TYPE,
  BGP_SAFI,
  type BgpAttrFlags,
} from './types';

export interface NamedRfcEntry {
  readonly name: string;
  readonly explanation: string;
  readonly reference: string;
}

export const WELL_KNOWN_COMMUNITIES = {
  NO_EXPORT: 0xffffff01,
  NO_ADVERTISE: 0xffffff02,
  NO_EXPORT_SUBCONFED: 0xffffff03,
  NOPEER: 0xffffff04,
  GRACEFUL_SHUTDOWN: 0xffff0000,
  BLACKHOLE: 0xffff029a,
} as const;

const WELL_KNOWN_COMMUNITY_INFO: Readonly<Record<number, NamedRfcEntry>> = {
  [WELL_KNOWN_COMMUNITIES.NO_EXPORT]: {
    name: 'NO_EXPORT',
    explanation: 'Do not advertise this route outside a BGP confederation or to external eBGP peers.',
    reference: 'RFC 1997 §3',
  },
  [WELL_KNOWN_COMMUNITIES.NO_ADVERTISE]: {
    name: 'NO_ADVERTISE',
    explanation: 'Do not advertise this route to any BGP peer (neither iBGP nor eBGP).',
    reference: 'RFC 1997 §3',
  },
  [WELL_KNOWN_COMMUNITIES.NO_EXPORT_SUBCONFED]: {
    name: 'NO_EXPORT_SUBCONFED',
    explanation: 'Do not advertise this route to external BGP peers, including peers in other confederation member ASes.',
    reference: 'RFC 1997 §3',
  },
  [WELL_KNOWN_COMMUNITIES.NOPEER]: {
    name: 'NOPEER',
    explanation: 'Request that receiving ASes do not re-advertise this route to bilateral peers.',
    reference: 'RFC 3765 §2',
  },
  [WELL_KNOWN_COMMUNITIES.GRACEFUL_SHUTDOWN]: {
    name: 'GRACEFUL_SHUTDOWN',
    explanation: 'Signal planned maintenance so peers lower LOCAL_PREF and drain traffic before shutdown.',
    reference: 'RFC 8326 §4',
  },
  [WELL_KNOWN_COMMUNITIES.BLACKHOLE]: {
    name: 'BLACKHOLE',
    explanation: 'Request that the peer discard (blackhole) traffic destined for this prefix, typically during a DDoS attack.',
    reference: 'RFC 7999 §2',
  },
};

export function makeCommunity(asn: number, value: number): number {
  return (((asn & 0xffff) << 16) | (value & 0xffff)) >>> 0;
}

export function formatCommunity(value: number): string {
  const unsigned = value >>> 0;
  const high = (unsigned >>> 16) & 0xffff;
  const low = unsigned & 0xffff;
  const wellKnown = WELL_KNOWN_COMMUNITY_INFO[unsigned];
  if (wellKnown) {
    return `${wellKnown.name} (${high}:${low})`;
  }
  return `${high}:${low}`;
}

export function getCommunityInfo(value: number): NamedRfcEntry {
  const unsigned = value >>> 0;
  const wellKnown = WELL_KNOWN_COMMUNITY_INFO[unsigned];
  if (wellKnown) return wellKnown;
  return {
    name: `${(unsigned >>> 16) & 0xffff}:${unsigned & 0xffff}`,
    explanation:
      'A 32-bit community tag formatted as ASN:Value used to group routes and apply routing policy across networks.',
    reference: 'RFC 1997 §2',
  };
}

export function getMessageTypeName(typeCode: number): string {
  switch (typeCode) {
    case BGP_MESSAGE_TYPE.OPEN:
      return 'OPEN';
    case BGP_MESSAGE_TYPE.UPDATE:
      return 'UPDATE';
    case BGP_MESSAGE_TYPE.NOTIFICATION:
      return 'NOTIFICATION';
    case BGP_MESSAGE_TYPE.KEEPALIVE:
      return 'KEEPALIVE';
    case BGP_MESSAGE_TYPE.ROUTE_REFRESH:
      return 'ROUTE-REFRESH';
    default:
      return `Unknown (${typeCode})`;
  }
}

export function getAfiName(afi: number): string {
  switch (afi) {
    case BGP_AFI.IPV4:
      return 'IPv4';
    case BGP_AFI.IPV6:
      return 'IPv6';
    case 25:
      return 'L2VPN';
    default:
      return `AFI ${afi}`;
  }
}

export function getSafiName(safi: number): string {
  switch (safi) {
    case BGP_SAFI.UNICAST:
      return 'Unicast';
    case BGP_SAFI.MULTICAST:
      return 'Multicast';
    case 4:
      return 'MPLS Labels';
    case 70:
      return 'EVPN';
    case 128:
      return 'MPLS-labeled VPN Unicast';
    default:
      return `SAFI ${safi}`;
  }
}

export function formatAfiSafi(afi: number, safi: number): string {
  return `${getAfiName(afi)} ${getSafiName(safi)} (AFI ${afi} / SAFI ${safi})`;
}

export function getOriginName(origin: number): string {
  switch (origin) {
    case 0:
      return 'IGP';
    case 1:
      return 'EGP';
    case 2:
      return 'INCOMPLETE';
    default:
      return `Unknown (${origin})`;
  }
}

export function getAsPathSegmentTypeName(segType: number): string {
  switch (segType) {
    case 1:
      return 'AS_SET';
    case 2:
      return 'AS_SEQUENCE';
    default:
      return `Unknown (${segType})`;
  }
}

export function getAddPathModeName(mode: number): string {
  switch (mode) {
    case 1:
      return 'Receive';
    case 2:
      return 'Send';
    case 3:
      return 'Send/Receive';
    default:
      return `Unknown (${mode})`;
  }
}

export function getRouteRefreshSubtypeInfo(subtype: number): NamedRfcEntry {
  switch (subtype) {
    case 0:
      return {
        name: 'Normal Route Refresh',
        explanation: 'Request the peer to re-advertise all routes for the specified AFI/SAFI.',
        reference: 'RFC 2918 §3',
      };
    case 1:
      return {
        name: 'BoRR (Beginning of Route Refresh)',
        explanation: 'Marks the start of a route refresh reply so the receiver can track stale routes.',
        reference: 'RFC 7313 §3.2',
      };
    case 2:
      return {
        name: 'EoRR (End of Route Refresh)',
        explanation: 'Marks the end of a route refresh reply so the receiver can sweep unrefreshed routes.',
        reference: 'RFC 7313 §3.2',
      };
    default:
      return {
        name: `Unknown Subtype (${subtype})`,
        explanation: 'Reserved/subtype octet in a ROUTE-REFRESH message (0 for standard refresh, 1/2 for Enhanced Route Refresh).',
        reference: 'RFC 2918 §3 / RFC 7313 §3.2',
      };
  }
}

export function getCapabilityInfo(code: number): NamedRfcEntry {
  switch (code) {
    case BGP_CAPABILITY_CODE.MULTIPROTOCOL:
      return {
        name: 'Multiprotocol Extensions',
        explanation: 'Advertises support for carrying routes of a specific Address Family (AFI) and Subsequent Address Family (SAFI).',
        reference: 'RFC 4760 §8',
      };
    case BGP_CAPABILITY_CODE.ROUTE_REFRESH:
      return {
        name: 'Route Refresh',
        explanation: 'Allows a speaker to ask its peer to re-send its Adj-RIB-Out without resetting the BGP session.',
        reference: 'RFC 2918 §2',
      };
    case BGP_CAPABILITY_CODE.GRACEFUL_RESTART:
      return {
        name: 'Graceful Restart',
        explanation: 'Allows a restarting router to preserve forwarding state while its BGP control plane reconnects.',
        reference: 'RFC 4724 §3',
      };
    case BGP_CAPABILITY_CODE.FOUR_OCTET_AS:
      return {
        name: 'Support for 4-octet AS Number',
        explanation: 'Advertises the speaker’s 32-bit ASN and enables 4-byte ASNs in AS_PATH and AGGREGATOR.',
        reference: 'RFC 6793 §3',
      };
    case BGP_CAPABILITY_CODE.ADD_PATH:
      return {
        name: 'ADD-PATH',
        explanation: 'Enables advertising multiple paths for the same prefix by prepending a 4-byte Path Identifier to each NLRI.',
        reference: 'RFC 7911 §4',
      };
    case BGP_CAPABILITY_CODE.ENHANCED_ROUTE_REFRESH:
      return {
        name: 'Enhanced Route Refresh',
        explanation: 'Adds BoRR/EoRR demarcation markers to Route Refresh replies so stale routes are purged safely.',
        reference: 'RFC 7313 §3.1',
      };
    default:
      return {
        name: `Unknown Capability (${code})`,
        explanation: 'An unrecognized or custom BGP capability carried in OPEN Optional Parameter Type 2.',
        reference: 'RFC 5492 §4',
      };
  }
}

export interface AttrSpec extends NamedRfcEntry {
  readonly defaultFlags: Omit<BgpAttrFlags, 'extendedLength'>;
}

const DEFAULT_ATTR_SPECS: Readonly<Record<number, AttrSpec>> = {
  [BGP_ATTR_TYPE.ORIGIN]: {
    name: 'ORIGIN',
    explanation: 'Indicates how the route originally entered BGP: IGP (0), EGP (1), or INCOMPLETE (2). Well-known mandatory.',
    reference: 'RFC 4271 §5.1.1',
    defaultFlags: { optional: false, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.AS_PATH]: {
    name: 'AS_PATH',
    explanation: 'Lists the Autonomous Systems the route traversed; used for loop detection and best-path selection.',
    reference: 'RFC 4271 §5.1.2',
    defaultFlags: { optional: false, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.NEXT_HOP]: {
    name: 'NEXT_HOP',
    explanation: 'IPv4 address of the next-hop router to use when forwarding packets toward the announced IPv4 NLRI prefixes.',
    reference: 'RFC 4271 §5.1.3',
    defaultFlags: { optional: false, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.MULTI_EXIT_DISC]: {
    name: 'MULTI_EXIT_DISC',
    explanation: 'Optional non-transitive metric hinting to a neighboring AS which entry point to prefer (lower is better).',
    reference: 'RFC 4271 §5.1.4',
    defaultFlags: { optional: true, transitive: false, partial: false },
  },
  [BGP_ATTR_TYPE.LOCAL_PREF]: {
    name: 'LOCAL_PREF',
    explanation: 'Well-known discretionary preference shared inside an AS (iBGP only; higher is better, omitted on eBGP).',
    reference: 'RFC 4271 §5.1.5',
    defaultFlags: { optional: false, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.ATOMIC_AGGREGATE]: {
    name: 'ATOMIC_AGGREGATE',
    explanation: 'Zero-length flag informing downstream speakers that a more-specific route was aggregated and AS path detail was lost.',
    reference: 'RFC 4271 §5.1.6',
    defaultFlags: { optional: false, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.AGGREGATOR]: {
    name: 'AGGREGATOR',
    explanation: 'Records the ASN and IPv4 BGP Identifier of the router that performed route aggregation.',
    reference: 'RFC 4271 §5.1.7',
    defaultFlags: { optional: true, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.COMMUNITIES]: {
    name: 'COMMUNITIES',
    explanation: 'List of 32-bit policy tags (ASN:Value or well-known names) attached to routes for traffic engineering and filtering.',
    reference: 'RFC 1997 §2',
  defaultFlags: { optional: true, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.MP_REACH_NLRI]: {
    name: 'MP_REACH_NLRI',
    explanation: 'Carries reachable prefixes and next-hop information for non-IPv4 address families such as IPv6 unicast.',
    reference: 'RFC 4760 §3',
    defaultFlags: { optional: true, transitive: false, partial: false },
  },
  [BGP_ATTR_TYPE.MP_UNREACH_NLRI]: {
    name: 'MP_UNREACH_NLRI',
    explanation: 'Withdraws previously advertised prefixes for a multiprotocol address family, or signals End-of-RIB when empty.',
    reference: 'RFC 4760 §4',
    defaultFlags: { optional: true, transitive: false, partial: false },
  },
  [BGP_ATTR_TYPE.AS4_PATH]: {
    name: 'AS4_PATH',
    explanation: 'Optional transitive 4-octet AS path carried across legacy 2-byte AS speakers to preserve 32-bit ASNs.',
    reference: 'RFC 6793 §4.2.2',
    defaultFlags: { optional: true, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.AS4_AGGREGATOR]: {
    name: 'AS4_AGGREGATOR',
    explanation: 'Optional transitive 4-octet aggregator attribute carrying the 32-bit ASN of an aggregating router across old peers.',
    reference: 'RFC 6793 §4.2.2',
    defaultFlags: { optional: true, transitive: true, partial: false },
  },
  [BGP_ATTR_TYPE.LARGE_COMMUNITY]: {
    name: 'LARGE_COMMUNITY',
    explanation: 'List of 96-bit community tags (GlobalAdmin:LocalData1:LocalData2) designed to work natively with 32-bit ASNs.',
    reference: 'RFC 8092 §3',
    defaultFlags: { optional: true, transitive: true, partial: false },
  },
};

export function getAttrSpec(typeCode: number): AttrSpec {
  return (
    DEFAULT_ATTR_SPECS[typeCode] ?? {
      name: `Unknown Attribute (${typeCode})`,
      explanation: 'An unrecognized or custom BGP path attribute.',
      reference: 'RFC 4271 §4.3',
      defaultFlags: { optional: true, transitive: true, partial: false },
    }
  );
}

// ---------------------------------------------------------------------------
// NOTIFICATION Error Codes & Subcodes (RFC 4271 §4.5/§6, RFC 4486, RFC 7313)
// ---------------------------------------------------------------------------

interface NotificationCodeEntry extends NamedRfcEntry {
  readonly subcodes: Readonly<Record<number, NamedRfcEntry>>;
}

const NOTIFICATION_TABLE: Readonly<Record<number, NotificationCodeEntry>> = {
  1: {
    name: 'Message Header Error',
    explanation: 'A syntax or framing error was detected in the 19-byte BGP common message header.',
    reference: 'RFC 4271 §6.1',
    subcodes: {
      1: {
        name: 'Connection Not Synchronized',
        explanation: 'The 16-byte Marker field did not contain all-ones (0xff).',
        reference: 'RFC 4271 §6.1',
      },
      2: {
        name: 'Bad Message Length',
        explanation: 'The Message Length was < 19, > 4096, or inconsistent with the message type.',
        reference: 'RFC 4271 §6.1',
      },
      3: {
        name: 'Bad Message Type',
        explanation: 'The Message Type field contained an unrecognized value.',
        reference: 'RFC 4271 §6.1',
      },
    },
  },
  2: {
    name: 'OPEN Message Error',
    explanation: 'An error was detected while validating a received BGP OPEN message.',
    reference: 'RFC 4271 §6.2',
    subcodes: {
      1: {
        name: 'Unsupported Version Number',
        explanation: 'The peer advertised a BGP version number not supported by this speaker (only BGP-4 is standard).',
        reference: 'RFC 4271 §6.2',
      },
      2: {
        name: 'Bad Peer AS',
        explanation: 'The ASN received in the peer’s OPEN did not match the configured neighbor AS.',
        reference: 'RFC 4271 §6.2',
      },
      3: {
        name: 'Bad BGP Identifier',
        explanation: 'The peer’s BGP Identifier was not a valid unicast IPv4 host address (e.g., 0.0.0.0).',
        reference: 'RFC 4271 §6.2',
      },
      4: {
        name: 'Unsupported Optional Parameter',
        explanation: 'One of the OPEN Optional Parameters is not recognized by the receiver.',
        reference: 'RFC 4271 §6.2',
      },
      5: {
        name: 'Authentication Failure (Deprecated)',
        explanation: 'Deprecated subcode formerly used for OPEN authentication errors.',
        reference: 'RFC 4271 §4.5',
      },
      6: {
        name: 'Unacceptable Hold Time',
        explanation: 'The proposed Hold Time was invalid (e.g., 1 or 2 seconds) or below policy minimum.',
        reference: 'RFC 4271 §6.2',
      },
      7: {
        name: 'Unsupported Capability',
        explanation: 'A required BGP capability was not supported by the remote peer.',
        reference: 'RFC 5492 §5',
      },
    },
  },
  3: {
    name: 'UPDATE Message Error',
    explanation: 'An error was detected in the attributes or NLRI of a received BGP UPDATE message.',
    reference: 'RFC 4271 §6.3',
    subcodes: {
      1: {
        name: 'Malformed Attribute List',
        explanation: 'The Total Path Attribute Length or an individual attribute length did not match the message bounds, or an attribute appeared twice.',
        reference: 'RFC 4271 §6.3',
      },
      2: {
        name: 'Unrecognized Well-known Attribute',
        explanation: 'A path attribute marked well-known (Optional=0) is unknown to this speaker.',
        reference: 'RFC 4271 §6.3',
      },
      3: {
        name: 'Missing Well-known Attribute',
        explanation: 'A mandatory well-known attribute (ORIGIN, AS_PATH, or NEXT_HOP for IPv4 NLRI) was absent from an UPDATE with NLRI.',
        reference: 'RFC 4271 §6.3',
      },
      4: {
        name: 'Attribute Flags Error',
        explanation: 'An attribute’s Optional/Transitive/Partial flags conflicted with the specification for its type code.',
        reference: 'RFC 4271 §6.3',
      },
      5: {
        name: 'Attribute Length Error',
        explanation: 'An attribute had an invalid value length for its type.',
        reference: 'RFC 4271 §6.3',
      },
      6: {
        name: 'Invalid ORIGIN Attribute',
        explanation: 'The ORIGIN attribute contained a value other than 0 (IGP), 1 (EGP), or 2 (INCOMPLETE).',
        reference: 'RFC 4271 §6.3',
      },
      7: {
        name: 'AS Routing Loop (Deprecated)',
        explanation: 'Deprecated subcode; AS path loops are handled silently by discarding the route rather than resetting the session.',
        reference: 'RFC 4271 §4.5',
      },
      8: {
        name: 'Invalid NEXT_HOP Attribute',
        explanation: 'The NEXT_HOP attribute was syntactically invalid or unusable.',
        reference: 'RFC 4271 §6.3',
      },
      9: {
        name: 'Optional Attribute Error',
        explanation: 'An optional path attribute was syntactically malformed.',
        reference: 'RFC 4271 §6.3',
      },
      10: {
        name: 'Invalid Network Field',
        explanation: 'An IPv4 prefix length exceeded 32 bits or extended past the end of the message.',
        reference: 'RFC 4271 §6.3',
      },
      11: {
        name: 'Malformed AS_PATH',
        explanation: 'The AS_PATH attribute failed syntactic validation (e.g., invalid segment type or truncated AS list).',
        reference: 'RFC 4271 §6.3',
      },
    },
  },
  4: {
    name: 'Hold Timer Expired',
    explanation: 'No KEEPALIVE, UPDATE, or NOTIFICATION was received before the negotiated Hold Timer elapsed.',
    reference: 'RFC 4271 §6.5',
    subcodes: {
      0: {
        name: 'Unspecific',
        explanation: 'Hold Timer Expired uses subcode 0 (no subcode distinction is defined).',
        reference: 'RFC 4271 §6.5',
      },
    },
  },
  5: {
    name: 'Finite State Machine Error',
    explanation: 'A BGP message was received in a session state where it is not permitted by the BGP FSM.',
    reference: 'RFC 4271 §6.6',
    subcodes: {
      0: {
        name: 'Unspecified Error',
        explanation: 'Generic BGP Finite State Machine error.',
        reference: 'RFC 4271 §6.6',
      },
      1: {
        name: 'Receive Unexpected Message in OpenSent State',
        explanation: 'Received a message other than OPEN or NOTIFICATION while in OpenSent state.',
        reference: 'RFC 6608 §3',
      },
      2: {
        name: 'Receive Unexpected Message in OpenConfirm State',
        explanation: 'Received a message other than KEEPALIVE or NOTIFICATION while in OpenConfirm state.',
        reference: 'RFC 6608 §3',
      },
      3: {
        name: 'Receive Unexpected Message in Established State',
        explanation: 'Received an unexpected message (such as OPEN) while in Established state.',
        reference: 'RFC 6608 §3',
      },
    },
  },
  6: {
    name: 'Cease',
    explanation: 'The session was closed deliberately for an administrative or operational reason rather than a protocol error.',
    reference: 'RFC 4271 §6.7 / RFC 4486 §4',
    subcodes: {
      1: {
        name: 'Maximum Number of Prefixes Reached',
        explanation: 'The peer advertised more prefixes than the configured maximum-prefix limit.',
        reference: 'RFC 4486 §4',
      },
      2: {
        name: 'Administrative Shutdown',
        explanation: 'An operator administratively shut down the BGP session or peer.',
        reference: 'RFC 4486 §4',
      },
      3: {
        name: 'Peer De-configured',
        explanation: 'The BGP neighbor configuration was removed on the sending router.',
        reference: 'RFC 4486 §4',
      },
      4: {
        name: 'Administrative Reset',
        explanation: 'An operator manually cleared/reset the BGP session.',
        reference: 'RFC 4486 §4',
      },
      5: {
        name: 'Connection Rejected',
        explanation: 'The router refused an incoming BGP TCP connection.',
        reference: 'RFC 4486 §4',
      },
      6: {
        name: 'Other Configuration Change',
        explanation: 'A configuration change required tearing down and re-establishing the session.',
        reference: 'RFC 4486 §4',
      },
      7: {
        name: 'Connection Collision Resolution',
        explanation: 'Two simultaneous BGP TCP connections were opened; this one was closed by RFC 4271 §6.8 tie-breaking.',
        reference: 'RFC 4486 §4',
      },
      8: {
        name: 'Out of Resources',
        explanation: 'The router lacked memory or system resources to sustain the session.',
        reference: 'RFC 4486 §4',
      },
      9: {
        name: 'Hard Reset',
        explanation: 'Signals a hard reset that overrides Graceful Restart preservation.',
        reference: 'RFC 8538 §3',
      },
    },
  },
  7: {
    name: 'ROUTE-REFRESH Message Error',
    explanation: 'A received ROUTE-REFRESH message failed validation.',
    reference: 'RFC 7313 §5',
    subcodes: {
      1: {
        name: 'Invalid Message Length',
        explanation: 'The ROUTE-REFRESH message length was not 23 octets.',
        reference: 'RFC 7313 §5',
      },
    },
  },
};

export function getNotificationErrorInfo(errorCode: number): NamedRfcEntry {
  const entry = NOTIFICATION_TABLE[errorCode];
  if (entry) {
    return { name: entry.name, explanation: entry.explanation, reference: entry.reference };
  }
  return {
    name: `Unknown Error Code (${errorCode})`,
    explanation: 'Unrecognized BGP NOTIFICATION error code.',
    reference: 'RFC 4271 §4.5',
  };
}

export function getNotificationSubcodeInfo(
  errorCode: number,
  errorSubcode: number,
): NamedRfcEntry {
  const codeEntry = NOTIFICATION_TABLE[errorCode];
  const sub = codeEntry?.subcodes[errorSubcode];
  if (sub) return sub;
  if (errorSubcode === 0) {
    return {
      name: 'Unspecific',
      explanation: 'No more specific error subcode was reported (0 = unspecific).',
      reference: codeEntry?.reference ?? 'RFC 4271 §4.5',
    };
  }
  return {
    name: `Unknown Subcode (${errorSubcode})`,
    explanation: `Unrecognized subcode ${errorSubcode} for NOTIFICATION error code ${errorCode}.`,
    reference: codeEntry?.reference ?? 'RFC 4271 §4.5',
  };
}
