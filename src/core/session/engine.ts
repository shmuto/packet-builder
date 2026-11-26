import {
  BGP_AFI,
  BGP_AS_TRANS,
  BGP_SAFI,
  createEndOfRib,
  encodeBgpMessage,
  formatAfiSafi,
  formatCommunity,
  getOriginName,
  isEndOfRib,
  type BgpCapability,
  type BgpCodecContext,
  type BgpMessage,
  type BgpOpenMessage,
  type BgpPathAttribute,
  type BgpUpdateMessage,
} from '../bgp';
import { buildMultiPcap, LINKTYPE_ETHERNET } from '../pcap';
import {
  BGP_TCP_PORT,
  buildTcpFrame,
  createTcpTracker,
  isIPv6Address,
  TCP_MSS_VALUE,
} from './framing';
import type {
  AddressFamilyId,
  BgpFsmPhase,
  CapabilityKey,
  CapabilityNegotiationEntry,
  NegotiatedState,
  OriginatedRoute,
  RouteOmission,
  RouterConfig,
  RouterId,
  SessionConfig,
  SessionEvent,
  SessionStep,
  SessionTrace,
  SessionType,
} from './types';

const DEFAULT_BASE_TIMESTAMP_MS = 1_700_000_000_000;
const DEFAULT_IBGP_LOCAL_PREF = 100;
const DEFAULT_GR_RESTART_TIME = 120;

const CAPABILITY_METADATA: readonly {
  readonly key: CapabilityKey;
  readonly label: string;
  readonly reference: string;
}[] = [
  { key: 'mpIpv4Unicast', label: 'MP IPv4 Unicast', reference: 'RFC 4760 §8' },
  { key: 'mpIpv6Unicast', label: 'MP IPv6 Unicast', reference: 'RFC 4760 §8' },
  { key: 'routeRefresh', label: 'Route Refresh', reference: 'RFC 2918 §2' },
  { key: 'fourOctetAs', label: '4-octet AS', reference: 'RFC 6793 §3' },
  { key: 'gracefulRestart', label: 'Graceful Restart', reference: 'RFC 4724 §3' },
];

function peerOf(id: RouterId): RouterId {
  return id === 'A' ? 'B' : 'A';
}

function getRouter(config: SessionConfig, id: RouterId): RouterConfig {
  return id === 'A' ? config.routerA : config.routerB;
}

function isIPv6Prefix(prefix: string): boolean {
  return prefix.includes(':');
}

function buildOpenCapabilities(router: RouterConfig): readonly BgpCapability[] {
  const caps: BgpCapability[] = [];
  const c = router.capabilities;

  if (c.mpIpv4Unicast) {
    caps.push({ kind: 'mp', afi: BGP_AFI.IPV4, safi: BGP_SAFI.UNICAST });
  }
  if (c.mpIpv6Unicast) {
    caps.push({ kind: 'mp', afi: BGP_AFI.IPV6, safi: BGP_SAFI.UNICAST });
  }
  if (c.routeRefresh) {
    caps.push({ kind: 'routeRefresh' });
  }
  if (c.gracefulRestart) {
    const tuples: { afi: number; safi: number; forwardingState: boolean }[] = [];
    if (c.mpIpv4Unicast || !c.mpIpv6Unicast) {
      tuples.push({ afi: BGP_AFI.IPV4, safi: BGP_SAFI.UNICAST, forwardingState: false });
    }
    if (c.mpIpv6Unicast) {
      tuples.push({ afi: BGP_AFI.IPV6, safi: BGP_SAFI.UNICAST, forwardingState: false });
    }
    caps.push({
      kind: 'gracefulRestart',
      restartFlags: 0,
      restartTime: DEFAULT_GR_RESTART_TIME,
      tuples,
    });
  }
  if (c.fourOctetAs) {
    caps.push({ kind: 'fourOctetAs', asn: router.asn });
  }

  return caps;
}

function buildOpenMessage(router: RouterConfig): BgpOpenMessage {
  return {
    type: 'open',
    version: 4,
    asn: router.asn,
    holdTime: router.holdTime,
    bgpIdentifier: router.routerId,
    capabilities: buildOpenCapabilities(router),
  };
}

function computeCapabilityEntries(
  routerA: RouterConfig,
  routerB: RouterConfig,
  aSent: boolean,
  bSent: boolean,
): readonly CapabilityNegotiationEntry[] {
  return CAPABILITY_METADATA.map(({ key, label, reference }) => {
    const advertisedByA = aSent ? routerA.capabilities[key] : false;
    const advertisedByB = bSent ? routerB.capabilities[key] : false;
    const active = aSent && bSent && advertisedByA && advertisedByB;
    return { key, label, advertisedByA, advertisedByB, active, reference };
  });
}

function computeActiveFamilies(
  routerA: RouterConfig,
  routerB: RouterConfig,
  negotiated: boolean,
): readonly AddressFamilyId[] {
  if (!negotiated) return [];
  const anyMpAdvertised =
    routerA.capabilities.mpIpv4Unicast ||
    routerB.capabilities.mpIpv4Unicast ||
    routerA.capabilities.mpIpv6Unicast ||
    routerB.capabilities.mpIpv6Unicast;

  const families: AddressFamilyId[] = [];
  if ((routerA.capabilities.mpIpv4Unicast && routerB.capabilities.mpIpv4Unicast) || !anyMpAdvertised) {
    families.push('ipv4-unicast');
  }
  if (routerA.capabilities.mpIpv6Unicast && routerB.capabilities.mpIpv6Unicast) {
    families.push('ipv6-unicast');
  }
  return families;
}

function buildCapabilityNegotiationExplanations(
  routerA: RouterConfig,
  routerB: RouterConfig,
  entries: readonly CapabilityNegotiationEntry[],
  activeFamilies: readonly AddressFamilyId[],
): readonly string[] {
  const lines: string[] = [];
  const activeNames = entries.filter((e) => e.active).map((e) => e.label);
  const inactiveReasons = entries
    .filter((e) => !e.active && (e.advertisedByA || e.advertisedByB))
    .map((e) => {
      const onlyBy = e.advertisedByA ? routerA.name : routerB.name;
      return `${e.label} (only advertised by ${onlyBy})`;
    });

  if (activeNames.length > 0) {
    lines.push(
      `Capabilities in effect (advertised by both ${routerA.name} and ${routerB.name}): ${activeNames.join(', ')} (RFC 5492 §3).`,
    );
  } else {
    lines.push(
      'No optional capabilities were advertised by both peers; falling back to classic RFC 4271 IPv4 unicast with 2-octet AS numbers (RFC 5492 §3).',
    );
  }

  if (inactiveReasons.length > 0) {
    lines.push(
      `Capabilities NOT in effect because both sides must advertise a capability for it to apply: ${inactiveReasons.join('; ')} (RFC 5492 §3).`,
    );
  }

  const ipv6RoutesConfigured = [...routerA.routes, ...routerB.routes].filter((r) =>
    isIPv6Prefix(r.prefix),
  );
  if (ipv6RoutesConfigured.length > 0 && !activeFamilies.includes('ipv6-unicast')) {
    lines.push(
      `Because MP IPv6 Unicast is not in effect on both sides, configured IPv6 routes (${ipv6RoutesConfigured.map((r) => r.prefix).join(', ')}) will not be advertised (RFC 4760 §8).`,
    );
  }

  return lines;
}

function summarizeBgpMessage(msg: BgpMessage, sender: RouterConfig): string {
  switch (msg.type) {
    case 'open':
      return `OPEN (AS ${msg.asn}, Hold ${msg.holdTime}s, ${msg.capabilities.length} ${msg.capabilities.length === 1 ? 'cap' : 'caps'})`;
    case 'keepalive':
      return 'KEEPALIVE';
    case 'notification':
      return `NOTIFICATION (${msg.errorCode}/${msg.errorSubcode})`;
    case 'routeRefresh':
      return `ROUTE-REFRESH (${formatAfiSafi(msg.afi, msg.safi)})`;
    case 'update': {
      const eor = isEndOfRib(msg);
      if (eor) {
        return eor.afi === BGP_AFI.IPV4
          ? 'End-of-RIB IPv4'
          : eor.afi === BGP_AFI.IPV6
            ? 'End-of-RIB IPv6'
            : `End-of-RIB (${eor.afi}/${eor.safi})`;
      }
      const mpReach = msg.pathAttributes.find((a) => a.kind === 'mpReachNlri');
      const mpUnreach = msg.pathAttributes.find((a) => a.kind === 'mpUnreachNlri');
      const parts: string[] = [];
      if (msg.nlri.length > 0) {
        parts.push(`+${msg.nlri.map((p) => p.prefix).join(', ')}`);
      }
      if (mpReach && mpReach.kind === 'mpReachNlri' && mpReach.nlri.length > 0) {
        parts.push(`+${mpReach.nlri.map((p) => p.prefix).join(', ')}`);
      }
      if (msg.withdrawnRoutes.length > 0) {
        parts.push(`-${msg.withdrawnRoutes.map((p) => p.prefix).join(', ')}`);
      }
      if (mpUnreach && mpUnreach.kind === 'mpUnreachNlri' && mpUnreach.withdrawnRoutes.length > 0) {
        parts.push(`-${mpUnreach.withdrawnRoutes.map((p) => p.prefix).join(', ')}`);
      }
      return parts.length > 0 ? `UPDATE ${parts.join(' ')}` : `UPDATE (${sender.name})`;
    }
    case 'unknown':
      return `BGP Type ${msg.typeCode}`;
  }
}

function selectRoutesForEvent(
  router: RouterConfig,
  routeIds?: readonly string[],
  prefixes?: readonly string[],
): readonly OriginatedRoute[] {
  if (!routeIds && !prefixes) {
    return router.routes;
  }
  const idSet = routeIds ? new Set(routeIds) : null;
  const prefixSet = prefixes ? new Set(prefixes) : null;
  return router.routes.filter(
    (r) => (idSet !== null && idSet.has(r.id)) || (prefixSet !== null && prefixSet.has(r.prefix)),
  );
}

function routeAttrGroupingKey(
  route: OriginatedRoute,
  sessionType: SessionType,
  sender: RouterConfig,
): string {
  const effectiveLocalPref =
    sessionType === 'ibgp' ? (route.localPref ?? sender.localPref ?? DEFAULT_IBGP_LOCAL_PREF) : null;
  return JSON.stringify({
    origin: route.origin,
    med: route.med ?? null,
    localPref: effectiveLocalPref,
    communities: route.communities ?? [],
    largeCommunities: route.largeCommunities ?? [],
  });
}

function resolveIpv6NextHop(sender: RouterConfig): string {
  if (isIPv6Address(sender.peeringAddress)) {
    return sender.peeringAddress;
  }
  if (sender.ipv6NextHop) {
    return sender.ipv6NextHop;
  }
  return `::ffff:${sender.peeringAddress}`;
}

function resolveIpv4NextHop(sender: RouterConfig): {
  readonly nextHop: string;
  readonly source: 'peering' | 'configured' | 'routerId';
} {
  if (!isIPv6Address(sender.peeringAddress)) {
    return { nextHop: sender.peeringAddress, source: 'peering' };
  }
  if (sender.ipv4NextHop) {
    return { nextHop: sender.ipv4NextHop, source: 'configured' };
  }
  return { nextHop: sender.routerId, source: 'routerId' };
}

/**
 * Simulates a two-router BGP session from configuration and ordered events,
 * producing a complete timeline of TCP + BGP frames, dissection trees,
 * per-step learner explanations, and negotiated state snapshots.
 */
export function buildSession(
  config: SessionConfig,
  events: readonly SessionEvent[],
): SessionTrace {
  const { routerA, routerB } = config;
  const sessionType: SessionType = routerA.asn !== routerB.asn ? 'ebgp' : 'ibgp';
  const baseTimestampMs = config.baseTimestampMs ?? DEFAULT_BASE_TIMESTAMP_MS;
  const tracker = createTcpTracker(routerA, routerB, sessionType);

  const steps: SessionStep[] = [];
  const omissions: RouteOmission[] = [];
  const notes: string[] = [];

  let phase: BgpFsmPhase = 'Idle';
  let openASent = false;
  let openBSent = false;
  let negotiatedHoldTime: number | null = null;
  let keepaliveInterval: number | null = null;
  let closedReason: string | undefined;
  let currentT = 0;
  const lastBgpRxTime: Record<RouterId, number> = { A: 0, B: 0 };
  const lastBgpTxTime: Record<RouterId, number> = { A: 0, B: 0 };

  const snapshotState = (): NegotiatedState => {
    const bothOpens = openASent && openBSent;
    const capabilities = computeCapabilityEntries(routerA, routerB, openASent, openBSent);
    const activeFamilies = computeActiveFamilies(routerA, routerB, bothOpens);
    const fourOctetAsActive =
      capabilities.find((c) => c.key === 'fourOctetAs')?.active ?? false;
    return {
      phase,
      sessionType,
      negotiatedHoldTime,
      keepaliveInterval,
      capabilities,
      activeFamilies,
      fourOctetAsActive,
      ...(closedReason ? { closedReason } : {}),
    };
  };

  const currentCodecContext = (): BgpCodecContext => {
    const state = snapshotState();
    return { fourOctetAs: state.fourOctetAsActive };
  };

  const emitTcp = (
    from: RouterId,
    summary: string,
    flags: Partial<{ syn: boolean; ack: boolean; fin: boolean; psh: boolean; rst: boolean }>,
    explanations: readonly string[],
    options: readonly { kind: 'mss'; mss: number }[] = [],
  ) => {
    const to = peerOf(from);
    const sender = getRouter(config, from);
    const receiver = getRouter(config, to);
    const built = buildTcpFrame({ from, sender, receiver, tracker, flags, options });
    steps.push({
      index: steps.length,
      t: currentT,
      timestampMs: baseTimestampMs + currentT,
      from,
      to,
      kind: 'tcp',
      summary,
      frameBytes: built.frameBytes,
      explanations,
      state: snapshotState(),
    });
  };

  const emitBgp = (
    from: RouterId,
    msg: BgpMessage,
    explanations: readonly string[],
    ackAfter = true,
  ) => {
    const to = peerOf(from);
    const sender = getRouter(config, from);
    const receiver = getRouter(config, to);
    const ctx = currentCodecContext();
    const encoded = encodeBgpMessage(msg, ctx);
    if (!encoded.ok) {
      throw new Error(`Failed to encode BGP ${msg.type} from ${from}: ${encoded.error}`);
    }
    const built = buildTcpFrame({
      from,
      sender,
      receiver,
      tracker,
      flags: { psh: true, ack: true },
      payload: encoded.value.bytes,
    });
    lastBgpTxTime[from] = currentT;
    lastBgpRxTime[to] = currentT;

    steps.push({
      index: steps.length,
      t: currentT,
      timestampMs: baseTimestampMs + currentT,
      from,
      to,
      kind: 'bgp',
      summary: summarizeBgpMessage(msg, sender),
      frameBytes: built.frameBytes,
      bgpOffset: built.payloadOffset,
      bgpMessage: msg,
      tree: encoded.value.tree,
      explanations,
      state: snapshotState(),
    });

    if (ackAfter) {
      currentT += 2;
      emitTcp(
        to,
        'TCP ACK',
        { ack: true },
        [`${receiver.name} acknowledges receipt of ${sender.name}’s ${msg.type.toUpperCase()} segment.`],
      );
    }
  };

  const emitTcpClose = (initiator: RouterId, reason: string) => {
    const responder = peerOf(initiator);
    const initRouter = getRouter(config, initiator);
    const respRouter = getRouter(config, responder);
    phase = 'Closed';
    closedReason = reason;

    currentT += 5;
    emitTcp(
      initiator,
      'TCP FIN+ACK',
      { fin: true, ack: true },
      [`${initRouter.name} closes the TCP session after ${reason} (RFC 4271 §8).`],
    );
    currentT += 2;
    emitTcp(
      responder,
      'TCP FIN+ACK',
      { fin: true, ack: true },
      [`${respRouter.name} acknowledges FIN and closes its half of the TCP connection.`],
    );
    currentT += 2;
    emitTcp(
      initiator,
      'TCP ACK',
      { ack: true },
      [`${initRouter.name} completes the TCP teardown.`],
    );
  };

  const emitEndOfRibFor = (routers: readonly RouterId[]) => {
    if (phase !== 'Established') return;
    const state = snapshotState();
    for (const rId of routers) {
      for (const family of state.activeFamilies) {
        currentT += 15;
        const afi = family === 'ipv4-unicast' ? BGP_AFI.IPV4 : BGP_AFI.IPV6;
        const eorMsg = createEndOfRib(afi, BGP_SAFI.UNICAST);
        const router = getRouter(config, rId);
        const familyLabel = family === 'ipv4-unicast' ? 'IPv4 Unicast' : 'IPv6 Unicast';
        const wireNote =
          family === 'ipv4-unicast'
            ? 'For IPv4 unicast, End-of-RIB is a minimal 23-byte UPDATE with zero withdrawn routes, zero path attributes, and zero NLRI (RFC 4724 §2).'
            : 'For IPv6 unicast, End-of-RIB is an UPDATE containing only an empty MP_UNREACH_NLRI for AFI 2 / SAFI 1 (RFC 4724 §2).';
        emitBgp(rId, eorMsg, [
          `${router.name} sends End-of-RIB for ${familyLabel} to mark completion of its initial route table dump.`,
          wireNote,
          'End-of-RIB was originally defined for Graceful Restart (RFC 4724 §2), but modern BGP speakers commonly send it even when Graceful Restart is not negotiated.',
        ]);
      }
    }
  };

  const handleEstablish = () => {
    // 1. TCP 3-way handshake A -> B:179
    phase = 'Connect';
    currentT = 0;
    emitTcp(
      'A',
      `TCP SYN (MSS ${TCP_MSS_VALUE})`,
      { syn: true },
      [
        `${routerA.name} initiates a TCP connection to ${routerB.name} port ${BGP_TCP_PORT} (BGP runs over TCP port 179, RFC 4271 §1).`,
        `Includes the TCP MSS (${TCP_MSS_VALUE}) option to negotiate maximum segment size.`,
      ],
      [{ kind: 'mss', mss: TCP_MSS_VALUE }],
    );

    currentT += 2;
    emitTcp(
      'B',
      `TCP SYN+ACK (MSS ${TCP_MSS_VALUE})`,
      { syn: true, ack: true },
      [`${routerB.name} accepts the TCP connection on port ${BGP_TCP_PORT}.`],
      [{ kind: 'mss', mss: TCP_MSS_VALUE }],
    );

    currentT += 2;
    emitTcp(
      'A',
      'TCP ACK',
      { ack: true },
      ['TCP three-way handshake is complete; routers now exchange BGP OPEN messages.'],
    );

    // 2. OPEN A -> B
    currentT += 6;
    phase = 'OpenSent';
    openASent = true;
    const openA = buildOpenMessage(routerA);
    const openAExplanations: string[] = [
      `${routerA.name} sends OPEN advertising AS ${routerA.asn}, Router ID ${routerA.routerId}, and Hold Time ${routerA.holdTime}s (RFC 4271 §4.2).`,
      sessionType === 'ebgp'
        ? `Because ${routerA.name} (AS ${routerA.asn}) and ${routerB.name} (AS ${routerB.asn}) are in different ASes, this is an eBGP session.`
        : `Because both routers are in AS ${routerA.asn}, this is an iBGP session.`,
    ];
    if (routerA.asn > 0xffff) {
      openAExplanations.push(
        routerA.capabilities.fourOctetAs
          ? `My AS is set to AS_TRANS (${BGP_AS_TRANS}) because AS ${routerA.asn} exceeds 65535; the full 32-bit ASN is carried in Capability 65 (RFC 6793 §3).`
          : `My AS is set to AS_TRANS (${BGP_AS_TRANS}) because AS ${routerA.asn} exceeds 65535, but 4-octet AS capability is disabled on ${routerA.name}, so the full 32-bit ASN is not carried in Capability 65 (RFC 6793 §3).`,
      );
    }
    emitBgp('A', openA, openAExplanations);

    // Check Bad Peer AS on B receiving A's OPEN
    if (routerB.expectedPeerAs !== undefined && routerB.expectedPeerAs !== routerA.asn) {
      currentT += 10;
      const reason = `Bad Peer AS (${routerB.name} expected AS ${routerB.expectedPeerAs}, received AS ${routerA.asn})`;
      closedReason = reason;
      emitBgp('B', { type: 'notification', errorCode: 2, errorSubcode: 2, dataHex: '' }, [
        `${routerB.name} rejects ${routerA.name}’s OPEN with NOTIFICATION 2/2 (OPEN Message Error / Bad Peer AS) because it expected peer AS ${routerB.expectedPeerAs} but received AS ${routerA.asn} (RFC 4271 §6.2).`,
      ]);
      emitTcpClose('B', reason);
      return;
    }

    // 3. OPEN B -> A
    currentT += 6;
    openBSent = true;
    negotiatedHoldTime = Math.min(routerA.holdTime, routerB.holdTime);
    keepaliveInterval = negotiatedHoldTime === 0 ? 0 : Math.floor(negotiatedHoldTime / 3);
    phase = 'OpenConfirm';

    const stateAfterOpens = snapshotState();
    const openB = buildOpenMessage(routerB);
    const openBExplanations: string[] = [
      `${routerB.name} responds with OPEN advertising AS ${routerB.asn}, Router ID ${routerB.routerId}, and Hold Time ${routerB.holdTime}s (RFC 4271 §4.2).`,
      negotiatedHoldTime === 0
        ? 'Negotiated Hold Time is 0s (smaller of the two OPEN Hold Times), so periodic KEEPALIVEs are disabled (RFC 4271 §4.2).'
        : `Negotiated Hold Time is ${negotiatedHoldTime}s (smaller of ${routerA.holdTime}s and ${routerB.holdTime}s, RFC 4271 §4.2); KEEPALIVE interval is ${keepaliveInterval}s (Hold Time / 3, RFC 4271 §10).`,
      ...buildCapabilityNegotiationExplanations(
        routerA,
        routerB,
        stateAfterOpens.capabilities,
        stateAfterOpens.activeFamilies,
      ),
    ];
    if (routerB.asn > 0xffff) {
      openBExplanations.push(
        routerB.capabilities.fourOctetAs
          ? `My AS is set to AS_TRANS (${BGP_AS_TRANS}) because AS ${routerB.asn} exceeds 65535; the full 32-bit ASN is carried in Capability 65 (RFC 6793 §3).`
          : `My AS is set to AS_TRANS (${BGP_AS_TRANS}) because AS ${routerB.asn} exceeds 65535, but 4-octet AS capability is disabled on ${routerB.name}, so the full 32-bit ASN is not carried in Capability 65 (RFC 6793 §3).`,
      );
    }
    emitBgp('B', openB, openBExplanations);

    // Check Bad Peer AS on A receiving B's OPEN
    if (routerA.expectedPeerAs !== undefined && routerA.expectedPeerAs !== routerB.asn) {
      currentT += 10;
      const reason = `Bad Peer AS (${routerA.name} expected AS ${routerA.expectedPeerAs}, received AS ${routerB.asn})`;
      closedReason = reason;
      emitBgp('A', { type: 'notification', errorCode: 2, errorSubcode: 2, dataHex: '' }, [
        `${routerA.name} rejects ${routerB.name}’s OPEN with NOTIFICATION 2/2 (OPEN Message Error / Bad Peer AS) because it expected peer AS ${routerA.expectedPeerAs} but received AS ${routerB.asn} (RFC 4271 §6.2).`,
      ]);
      emitTcpClose('A', reason);
      return;
    }

    // 4. Initial KEEPALIVE exchange (OpenConfirm -> Established, RFC 4271 §8)
    currentT += 8;
    emitBgp('A', { type: 'keepalive' }, [
      `${routerA.name} sends KEEPALIVE to accept ${routerB.name}’s OPEN parameters (RFC 4271 §8).`,
    ]);

    currentT += 6;
    phase = 'Established';
    emitBgp('B', { type: 'keepalive' }, [
      `${routerB.name} sends KEEPALIVE confirming ${routerA.name}’s OPEN; the BGP session is now Established and ready to exchange UPDATEs (RFC 4271 §8).`,
    ]);
  };

  const handleAdvertise = (
    routerId: RouterId,
    routeIds?: readonly string[],
    prefixes?: readonly string[],
  ) => {
    if (phase !== 'Established') return;
    const sender = getRouter(config, routerId);
    const state = snapshotState();
    const selected = selectRoutesForEvent(sender, routeIds, prefixes);

    const v4Routes = selected.filter((r) => !isIPv6Prefix(r.prefix));
    const v6Routes = selected.filter((r) => isIPv6Prefix(r.prefix));

    const emitFamilyGroup = (family: AddressFamilyId, routes: readonly OriginatedRoute[]) => {
      if (routes.length === 0) return;

      if (!state.activeFamilies.includes(family)) {
        const capLabel = family === 'ipv6-unicast' ? 'MP IPv6 Unicast' : 'MP IPv4 Unicast';
        for (const r of routes) {
          omissions.push({
            router: routerId,
            prefix: r.prefix,
            reason: `${sender.name} did not advertise ${r.prefix} because ${capLabel} was not negotiated by both peers (RFC 4760 §8 / RFC 5492 §3).`,
            reference: 'RFC 4760 §8 / RFC 5492 §3',
          });
        }
        return;
      }

      // Pack routes with identical attributes into one UPDATE (RFC 4271 §4.3)
      const groups = new Map<string, OriginatedRoute[]>();
      for (const r of routes) {
        const key = routeAttrGroupingKey(r, sessionType, sender);
        const list = groups.get(key);
        if (list) list.push(r);
        else groups.set(key, [r]);
      }

      for (const group of groups.values()) {
        currentT += 20;
        const sample = group[0];
        const attrs: BgpPathAttribute[] = [];
        const explanations: string[] = [];

        // ORIGIN (mandatory)
        attrs.push({ kind: 'origin', origin: sample.origin });

        // AS_PATH (+ AS4_PATH if eBGP, 4-octet AS not active, and ASN > 65535)
        const needsAsTrans =
          sessionType === 'ebgp' && !state.fourOctetAsActive && sender.asn > 0xffff;
        if (sessionType === 'ebgp') {
          if (needsAsTrans) {
            attrs.push({ kind: 'asPath', segments: [{ type: 2, asns: [BGP_AS_TRANS] }] });
          } else {
            attrs.push({ kind: 'asPath', segments: [{ type: 2, asns: [sender.asn] }] });
          }
          explanations.push(
            needsAsTrans
              ? `eBGP prepends ${sender.name}’s ASN, but 4-octet AS was not negotiated and AS ${sender.asn} > 65535: AS_PATH carries AS_TRANS (${BGP_AS_TRANS}) and AS4_PATH carries ${sender.asn} (RFC 6793 §4.2.2).`
              : `eBGP prepends ${sender.name}’s ASN (${sender.asn}) to AS_PATH using ${state.fourOctetAsActive ? '4-byte' : '2-byte'} AS encoding (RFC 4271 §5.1.2).`,
          );
        } else {
          attrs.push({ kind: 'asPath', segments: [] });
          explanations.push(
            `AS_PATH is empty because this is an iBGP session; routers do not prepend their own ASN on iBGP announcements (RFC 4271 §5.1.2).`,
          );
        }

        // NEXT_HOP (for IPv4 NLRI)
        if (family === 'ipv4-unicast') {
          const { nextHop, source } = resolveIpv4NextHop(sender);
          attrs.push({ kind: 'nextHop', nextHop });
          if (source === 'peering') {
            explanations.push(
              `NEXT_HOP is set to ${sender.name}’s peering address ${nextHop} (RFC 4271 §5.1.3).`,
            );
          } else if (source === 'configured') {
            explanations.push(
              `Because this is an IPv6 peering session, IPv4 NEXT_HOP uses ${sender.name}’s configured ipv4NextHop ${nextHop} (RFC 4271 §5.1.3).`,
            );
          } else {
            explanations.push(
              `Because this is an IPv6 peering session with no ipv4NextHop configured, IPv4 NEXT_HOP falls back to ${sender.name}’s Router ID ${nextHop} in this simulator (RFC 4271 §5.1.3).`,
            );
          }
        }

        // MULTI_EXIT_DISC (optional)
        if (sample.med !== undefined) {
          attrs.push({ kind: 'med', med: sample.med });
          explanations.push(
            `MULTI_EXIT_DISC (${sample.med}) hints to the peer which entry path to prefer; lower MED wins (RFC 4271 §5.1.4).`,
          );
        }

        // LOCAL_PREF (iBGP only)
        if (sessionType === 'ibgp') {
          const lp = sample.localPref ?? sender.localPref ?? DEFAULT_IBGP_LOCAL_PREF;
          attrs.push({ kind: 'localPref', localPref: lp });
          explanations.push(
            `LOCAL_PREF (${lp}) is included because this is an iBGP session; higher values are preferred within the AS (RFC 4271 §5.1.5).`,
          );
        } else {
          explanations.push(
            'LOCAL_PREF is absent because this is an eBGP session (RFC 4271 §5.1.5).',
          );
        }

        // COMMUNITIES
        if (sample.communities && sample.communities.length > 0) {
          attrs.push({ kind: 'communities', communities: sample.communities });
          explanations.push(
            `COMMUNITIES carries ${sample.communities.map((c) => formatCommunity(c)).join(', ')} for policy signaling (RFC 1997 §2).`,
          );
        }

        // MP_REACH_NLRI (for IPv6 unicast)
        if (family === 'ipv6-unicast') {
          const v6NextHop = resolveIpv6NextHop(sender);
          attrs.push({
            kind: 'mpReachNlri',
            afi: BGP_AFI.IPV6,
            safi: BGP_SAFI.UNICAST,
            nextHops: [v6NextHop],
            nlri: group.map((r) => ({ prefix: r.prefix })),
          });
          explanations.push(
            `IPv6 prefixes and next hop (${v6NextHop}) are carried in MP_REACH_NLRI (AFI 2 / SAFI 1) because MP IPv6 Unicast is active (RFC 4760 §3).`,
          );
        }

        // AS4_PATH (when 4-octet AS not active and ASN > 65535)
        if (needsAsTrans) {
          attrs.push({ kind: 'as4Path', segments: [{ type: 2, asns: [sender.asn] }] });
        }

        // LARGE_COMMUNITY
        if (sample.largeCommunities && sample.largeCommunities.length > 0) {
          attrs.push({ kind: 'largeCommunities', communities: sample.largeCommunities });
          explanations.push(
            `LARGE_COMMUNITY carries ${sample.largeCommunities.map((c) => `${c.globalAdmin}:${c.localData1}:${c.localData2}`).join(', ')} (RFC 8092 §3).`,
          );
        }

        if (group.length > 1) {
          explanations.push(
            `${group.length} prefixes (${group.map((r) => r.prefix).join(', ')}) share identical path attributes (${getOriginName(sample.origin)}) and are packed into one UPDATE (RFC 4271 §4.3).`,
          );
        }

        const updateMsg: BgpUpdateMessage = {
          type: 'update',
          withdrawnRoutes: [],
          pathAttributes: attrs,
          nlri: family === 'ipv4-unicast' ? group.map((r) => ({ prefix: r.prefix })) : [],
        };

        emitBgp(routerId, updateMsg, explanations);
      }
    };

    emitFamilyGroup('ipv4-unicast', v4Routes);
    emitFamilyGroup('ipv6-unicast', v6Routes);
  };

  const handleWithdraw = (
    routerId: RouterId,
    routeIds?: readonly string[],
    prefixes?: readonly string[],
  ) => {
    if (phase !== 'Established') return;
    const sender = getRouter(config, routerId);
    const state = snapshotState();
    const selected = selectRoutesForEvent(sender, routeIds, prefixes);

    const v4Prefixes = selected.filter((r) => !isIPv6Prefix(r.prefix)).map((r) => r.prefix);
    const v6Prefixes = selected.filter((r) => isIPv6Prefix(r.prefix)).map((r) => r.prefix);

    if (v4Prefixes.length > 0) {
      if (!state.activeFamilies.includes('ipv4-unicast')) {
        for (const prefix of v4Prefixes) {
          omissions.push({
            router: routerId,
            prefix,
            reason: `${sender.name} did not withdraw ${prefix} because MP IPv4 Unicast was not negotiated by both peers (RFC 4760 §8 / RFC 5492 §3).`,
            reference: 'RFC 4760 §8 / RFC 5492 §3',
          });
        }
      } else {
        currentT += 20;
        const withdrawMsg: BgpUpdateMessage = {
          type: 'update',
          withdrawnRoutes: v4Prefixes.map((prefix) => ({ prefix })),
          pathAttributes: [],
          nlri: [],
        };
        emitBgp(routerId, withdrawMsg, [
          `${sender.name} withdraws IPv4 prefix${v4Prefixes.length === 1 ? '' : 'es'} ${v4Prefixes.join(', ')} using the Withdrawn Routes field; no path attributes are required for withdrawals (RFC 4271 §4.3).`,
        ]);
      }
    }

    if (v6Prefixes.length > 0) {
      if (!state.activeFamilies.includes('ipv6-unicast')) {
        for (const prefix of v6Prefixes) {
          omissions.push({
            router: routerId,
            prefix,
            reason: `${sender.name} did not withdraw ${prefix} because MP IPv6 Unicast was not negotiated by both peers (RFC 4760 §8 / RFC 5492 §3).`,
            reference: 'RFC 4760 §8 / RFC 5492 §3',
          });
        }
      } else {
        currentT += 20;
        const withdrawMsg: BgpUpdateMessage = {
          type: 'update',
          withdrawnRoutes: [],
          pathAttributes: [
            {
              kind: 'mpUnreachNlri',
              afi: BGP_AFI.IPV6,
              safi: BGP_SAFI.UNICAST,
              withdrawnRoutes: v6Prefixes.map((prefix) => ({ prefix })),
            },
          ],
          nlri: [],
        };
        emitBgp(routerId, withdrawMsg, [
          `${sender.name} withdraws IPv6 prefix${v6Prefixes.length === 1 ? '' : 'es'} ${v6Prefixes.join(', ')} using MP_UNREACH_NLRI (AFI 2 / SAFI 1) (RFC 4760 §4).`,
        ]);
      }
    }
  };

  const handleHoldTimerExpires = (routerId: RouterId) => {
    if (phase !== 'Established') return;
    const router = getRouter(config, routerId);
    const peer = getRouter(config, peerOf(routerId));
    const holdSec = negotiatedHoldTime ?? 0;
    const kaSec = keepaliveInterval ?? 0;

    // RFC 4271 §4.2: When the negotiated Hold Time is 0, neither periodic KEEPALIVEs
    // nor the Hold Timer run, so a holdTimerExpires event cannot tear down the session.
    if (holdSec === 0) {
      notes.push(
        `Hold Timer expiry event for ${router.name} did not fire because the negotiated Hold Time is 0s, which disables both periodic KEEPALIVEs and the Hold Timer (RFC 4271 §4.2).`,
      );
      return;
    }

    const lastRx = lastBgpRxTime[routerId];
    const lastTx = lastBgpTxTime[routerId];
    const expiryTime = lastRx + holdSec * 1000;

    // Emit periodic KEEPALIVEs from `routerId` at the negotiated interval from its last TX time
    // while the peer remains silent until Hold Timer expiry (lastRx + holdSec * 1000).
    if (kaSec > 0) {
      for (let kaTime = lastTx + kaSec * 1000; kaTime + 2 < expiryTime; kaTime += kaSec * 1000) {
        if (kaTime > currentT) {
          currentT = kaTime;
          emitBgp(routerId, { type: 'keepalive' }, [
            `${router.name} sends a periodic KEEPALIVE at the negotiated ${kaSec}s interval (Hold Time ${holdSec}s / 3, RFC 4271 §10), while ${peer.name} remains silent.`,
          ]);
        }
      }
    }

    // Hold Timer expires exactly Hold Time after the last BGP message received from peer
    currentT = Math.max(currentT + 1, expiryTime);

    const reason = `Hold Timer Expired (${holdSec}s elapsed with no BGP message from ${peer.name})`;
    closedReason = reason;
    emitBgp(routerId, { type: 'notification', errorCode: 4, errorSubcode: 0, dataHex: '' }, [
      `${router.name}’s Hold Timer expired ${holdSec}s after the last BGP message from ${peer.name}, triggering NOTIFICATION 4/0 (Hold Timer Expired) and session teardown (RFC 4271 §6.5).`,
    ]);
    emitTcpClose(routerId, reason);
  };

  const handleAdminShutdown = (routerId: RouterId) => {
    if (phase !== 'Established') return;
    const router = getRouter(config, routerId);
    currentT += 1000;
    const reason = `Administrative Shutdown by ${router.name}`;
    closedReason = reason;
    emitBgp(routerId, { type: 'notification', errorCode: 6, errorSubcode: 2, dataHex: '' }, [
      `${router.name} sends NOTIFICATION 6/2 (Cease / Administrative Shutdown) because an operator administratively shut down the session (RFC 4486 §4).`,
    ]);
    emitTcpClose(routerId, reason);
  };

  const getPhase = (): BgpFsmPhase => phase;
  const hasExplicitEndOfRib = events.some((e) => e.type === 'endOfRib');
  let sawInitialAdvertise = false;
  let autoEndOfRibSent = false;

  for (const event of events) {
    if (getPhase() === 'Closed') break;

    if (
      !hasExplicitEndOfRib &&
      sawInitialAdvertise &&
      !autoEndOfRibSent &&
      event.type !== 'advertise'
    ) {
      emitEndOfRibFor(['A', 'B']);
      autoEndOfRibSent = true;
    }

    switch (event.type) {
      case 'establish':
        handleEstablish();
        break;
      case 'advertise':
        handleAdvertise(event.router, event.routeIds, event.prefixes);
        sawInitialAdvertise = true;
        break;
      case 'withdraw':
        handleWithdraw(event.router, event.routeIds, event.prefixes);
        break;
      case 'endOfRib':
        emitEndOfRibFor(event.router ? [event.router] : ['A', 'B']);
        autoEndOfRibSent = true;
        break;
      case 'holdTimerExpires':
        handleHoldTimerExpires(event.router);
        break;
      case 'adminShutdown':
        handleAdminShutdown(event.router);
        break;
    }
  }

  if (
    !hasExplicitEndOfRib &&
    sawInitialAdvertise &&
    !autoEndOfRibSent &&
    getPhase() === 'Established'
  ) {
    emitEndOfRibFor(['A', 'B']);
  }

  return {
    config,
    events,
    steps,
    omissions,
    notes,
    finalState: snapshotState(),
  };
}

/**
 * Exports all frames in a SessionTrace into a single multi-packet libpcap file
 * with per-packet synthetic timestamps ready to open in Wireshark or tshark.
 */
export function exportSessionPcap(trace: SessionTrace): Uint8Array {
  return buildMultiPcap(
    trace.steps.map((step) => ({
      bytes: step.frameBytes,
      timestampMs: step.timestampMs,
    })),
    { linkType: LINKTYPE_ETHERNET },
  );
}
