import { describe, expect, it } from 'vitest';
import {
  BGP_AFI,
  BGP_AS_TRANS,
  BGP_SAFI,
  isEndOfRib,
  makeCommunity,
} from '../bgp';
import { readUint32BE } from '../bytes';
import { PCAP_MAGIC_MICROSECONDS } from '../pcap';
import {
  buildSession,
  EBGP_IPV4_BASIC_SCENARIO,
  exportSessionPcap,
  type RouterCapabilities,
  type RouterConfig,
  type SessionConfig,
  type SessionStep,
} from './index';

function bgpSteps(steps: readonly SessionStep[]): readonly SessionStep[] {
  return steps.filter((s) => s.kind === 'bgp');
}

type RouterOverride = Omit<Partial<RouterConfig>, 'capabilities'> & {
  readonly capabilities?: Partial<RouterCapabilities>;
};

function makeBaseConfig(overrides?: {
  routerA?: RouterOverride;
  routerB?: RouterOverride;
}): SessionConfig {
  return {
    baseTimestampMs: 1_700_000_000_000,
    routerA: {
      ...EBGP_IPV4_BASIC_SCENARIO.config.routerA,
      ...overrides?.routerA,
      capabilities: {
        ...EBGP_IPV4_BASIC_SCENARIO.config.routerA.capabilities,
        ...overrides?.routerA?.capabilities,
      },
    },
    routerB: {
      ...EBGP_IPV4_BASIC_SCENARIO.config.routerB,
      ...overrides?.routerB,
      capabilities: {
        ...EBGP_IPV4_BASIC_SCENARIO.config.routerB.capabilities,
        ...overrides?.routerB?.capabilities,
      },
    },
  };
}

describe('BGP session scenario engine', () => {
  it('builds ebgp-ipv4-basic with expected message sequence, TCP seq/ack consistency, and multi-packet pcap', () => {
    const trace = buildSession(
      EBGP_IPV4_BASIC_SCENARIO.config,
      EBGP_IPV4_BASIC_SCENARIO.events,
    );

    const bgp = bgpSteps(trace.steps);
    expect(bgp.map((s) => `${s.from}->${s.to} ${s.summary}`)).toEqual([
      'A->B OPEN (AS 65001, Hold 90s, 3 caps)',
      'B->A OPEN (AS 65002, Hold 90s, 3 caps)',
      'A->B KEEPALIVE',
      'B->A KEEPALIVE',
      'A->B UPDATE +203.0.113.0/24',
      'B->A UPDATE +198.51.100.0/24',
      'A->B End-of-RIB IPv4',
      'B->A End-of-RIB IPv4',
      'A->B UPDATE -203.0.113.0/24',
    ]);

    expect(trace.finalState.phase).toBe('Established');
    expect(trace.finalState.sessionType).toBe('ebgp');
    expect(trace.finalState.negotiatedHoldTime).toBe(90);
    expect(trace.finalState.keepaliveInterval).toBe(30);
    expect(trace.omissions).toEqual([]);

    // Verify eBGP UPDATE rules on A->B advertisement
    const updateA = bgp[4];
    expect(updateA.bgpMessage?.type).toBe('update');
    if (updateA.bgpMessage?.type === 'update') {
      expect(updateA.bgpMessage.pathAttributes.some((a) => a.kind === 'localPref')).toBe(false);
      const asPath = updateA.bgpMessage.pathAttributes.find((a) => a.kind === 'asPath');
      expect(asPath?.kind === 'asPath' && asPath.segments).toEqual([{ type: 2, asns: [65001] }]);
      const nh = updateA.bgpMessage.pathAttributes.find((a) => a.kind === 'nextHop');
      expect(nh?.kind === 'nextHop' && nh.nextHop).toBe('192.0.2.1');
    }
    expect(updateA.explanations.some((e) => e.includes('LOCAL_PREF is absent'))).toBe(true);

    // Verify TCP sequence numbers monotonically advance and match peer ACKs (Ethernet 14 + IPv4 20 = 34)
    let expectedSeqA = 1000;
    let expectedSeqB = 2000;
    for (const step of trace.steps) {
      const tcpStart = 14 + 20;
      const seq = readUint32BE(step.frameBytes, tcpStart + 4);
      const ack = readUint32BE(step.frameBytes, tcpStart + 8);
      const dataOffset = (step.frameBytes[tcpStart + 12] >>> 4) * 4;
      const flags = step.frameBytes[tcpStart + 13];
      const payloadLen = step.frameBytes.length - (tcpStart + dataOffset);
      const syn = (flags & 0x02) !== 0;
      const fin = (flags & 0x01) !== 0;
      const hasAck = (flags & 0x10) !== 0;

      if (step.from === 'A') {
        expect(seq).toBe(expectedSeqA);
        if (hasAck) expect(ack).toBe(expectedSeqB);
        expectedSeqA += payloadLen + (syn ? 1 : 0) + (fin ? 1 : 0);
      } else {
        expect(seq).toBe(expectedSeqB);
        if (hasAck) expect(ack).toBe(expectedSeqA);
        expectedSeqB += payloadLen + (syn ? 1 : 0) + (fin ? 1 : 0);
      }
    }

    // Verify multi-packet pcap export
    const pcap = exportSessionPcap(trace);
    const view = new DataView(pcap.buffer);
    expect(view.getUint32(0, true)).toBe(PCAP_MAGIC_MICROSECONDS);
    expect(pcap.length).toBeGreaterThan(24 + trace.steps.length * 16);
  });

  it('negotiates the smaller Hold Time and disables periodic KEEPALIVEs when Hold Time is 0', () => {
    const cfg1 = makeBaseConfig({
      routerA: { holdTime: 180 },
      routerB: { holdTime: 60 },
    });
    const trace1 = buildSession(cfg1, [{ type: 'establish' }]);
    expect(trace1.finalState.negotiatedHoldTime).toBe(60);
    expect(trace1.finalState.keepaliveInterval).toBe(20);

    const cfg0 = makeBaseConfig({
      routerA: { holdTime: 0 },
      routerB: { holdTime: 90 },
    });
    const trace0 = buildSession(cfg0, [{ type: 'establish' }]);
    expect(trace0.finalState.negotiatedHoldTime).toBe(0);
    expect(trace0.finalState.keepaliveInterval).toBe(0);
  });

  it('intersects capabilities and omits IPv6 routes with an explanation when MP IPv6 is not active on both sides', () => {
    const cfg = makeBaseConfig({
      routerA: {
        capabilities: { mpIpv4Unicast: true, mpIpv6Unicast: true, gracefulRestart: true },
        routes: [
          { id: 'v4', prefix: '203.0.113.0/24', origin: 0 },
          { id: 'v6', prefix: '2001:db8:1::/48', origin: 0 },
        ],
      },
      routerB: {
        capabilities: { mpIpv4Unicast: true, mpIpv6Unicast: false, gracefulRestart: false },
        routes: [],
      },
    });

    const trace = buildSession(cfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
    ]);

    const mpV6Cap = trace.finalState.capabilities.find((c) => c.key === 'mpIpv6Unicast');
    expect(mpV6Cap?.advertisedByA).toBe(true);
    expect(mpV6Cap?.advertisedByB).toBe(false);
    expect(mpV6Cap?.active).toBe(false);
    expect(trace.finalState.activeFamilies).toEqual(['ipv4-unicast']);

    // IPv6 route must NOT appear in any UPDATE frame
    const updates = bgpSteps(trace.steps).filter((s) => s.bgpMessage?.type === 'update');
    expect(
      updates.some(
        (u) =>
          u.bgpMessage?.type === 'update' &&
          u.bgpMessage.pathAttributes.some((a) => a.kind === 'mpReachNlri'),
      ),
    ).toBe(false);

    // Omission and OPEN explanation both explain why
    expect(trace.omissions).toHaveLength(1);
    expect(trace.omissions[0].prefix).toBe('2001:db8:1::/48');
    expect(trace.omissions[0].reason).toContain('MP IPv6 Unicast');

    const openB = bgpSteps(trace.steps)[1];
    expect(openB.explanations.some((e) => e.includes('MP IPv6 Unicast'))).toBe(true);
  });

  it('applies iBGP attribute rules (LOCAL_PREF, empty AS_PATH) and IPv6 MP_REACH/MP_UNREACH + End-of-RIB per family', () => {
    const cfg = makeBaseConfig({
      routerA: {
        asn: 65001,
        localPref: 150,
        peeringAddress: '2001:db8::1',
        capabilities: { mpIpv4Unicast: true, mpIpv6Unicast: true, fourOctetAs: true },
        routes: [
          { id: 'v4', prefix: '203.0.113.0/24', origin: 0 },
          { id: 'v6', prefix: '2001:db8:1::/48', origin: 0 },
        ],
      },
      routerB: {
        asn: 65001,
        peeringAddress: '2001:db8::2',
        capabilities: { mpIpv4Unicast: true, mpIpv6Unicast: true, fourOctetAs: true },
        routes: [],
      },
    });

    const trace = buildSession(cfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
      { type: 'withdraw', router: 'A', routeIds: ['v6'] },
    ]);

    expect(trace.finalState.sessionType).toBe('ibgp');
    expect(trace.finalState.activeFamilies).toEqual(['ipv4-unicast', 'ipv6-unicast']);

    const bgp = bgpSteps(trace.steps);
    const v4Adv = bgp.find((s) => s.summary === 'UPDATE +203.0.113.0/24');
    const v6Adv = bgp.find((s) => s.summary === 'UPDATE +2001:db8:1::/48');
    const v6Wdr = bgp.find((s) => s.summary === 'UPDATE -2001:db8:1::/48');
    const eors = bgp.filter((s) => s.bgpMessage && isEndOfRib(s.bgpMessage) !== null);

    expect(v4Adv).toBeDefined();
    expect(v6Adv).toBeDefined();
    expect(v6Wdr).toBeDefined();
    // 2 routers x 2 active families = 4 End-of-RIB messages
    expect(eors).toHaveLength(4);
    expect(eors.filter((e) => isEndOfRib(e.bgpMessage!)?.afi === BGP_AFI.IPV4)).toHaveLength(2);
    expect(eors.filter((e) => isEndOfRib(e.bgpMessage!)?.afi === BGP_AFI.IPV6)).toHaveLength(2);

    // Check iBGP rules on IPv6 advertisement: empty AS_PATH + LOCAL_PREF 150 + MP_REACH_NLRI
    if (v6Adv?.bgpMessage?.type === 'update') {
      const asPath = v6Adv.bgpMessage.pathAttributes.find((a) => a.kind === 'asPath');
      const lp = v6Adv.bgpMessage.pathAttributes.find((a) => a.kind === 'localPref');
      const mp = v6Adv.bgpMessage.pathAttributes.find((a) => a.kind === 'mpReachNlri');
      expect(asPath?.kind === 'asPath' && asPath.segments).toEqual([]);
      expect(lp?.kind === 'localPref' && lp.localPref).toBe(150);
      expect(mp?.kind === 'mpReachNlri' && mp.afi).toBe(BGP_AFI.IPV6);
      expect(mp?.kind === 'mpReachNlri' && mp.safi).toBe(BGP_SAFI.UNICAST);
      expect(mp?.kind === 'mpReachNlri' && mp.nextHops).toEqual(['2001:db8::1']);
    }
  });

  it('uses AS_TRANS and AS4_PATH when 4-octet AS is not active and ASN > 65535', () => {
    const cfg = makeBaseConfig({
      routerA: {
        asn: 65551,
        capabilities: { fourOctetAs: true },
        routes: [{ id: 'r1', prefix: '203.0.113.0/24', origin: 0 }],
      },
      routerB: {
        asn: 65002,
        capabilities: { fourOctetAs: false },
        routes: [],
      },
    });

    const trace = buildSession(cfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
    ]);

    expect(trace.finalState.fourOctetAsActive).toBe(false);
    const adv = bgpSteps(trace.steps).find((s) => s.summary === 'UPDATE +203.0.113.0/24');
    expect(adv).toBeDefined();
    if (adv?.bgpMessage?.type === 'update') {
      const asPath = adv.bgpMessage.pathAttributes.find((a) => a.kind === 'asPath');
      const as4Path = adv.bgpMessage.pathAttributes.find((a) => a.kind === 'as4Path');
      expect(asPath?.kind === 'asPath' && asPath.segments).toEqual([
        { type: 2, asns: [BGP_AS_TRANS] },
      ]);
      expect(as4Path?.kind === 'as4Path' && as4Path.segments).toEqual([
        { type: 2, asns: [65551] },
      ]);
    }
    expect(adv?.explanations.some((e) => e.includes('AS_TRANS') && e.includes('AS4_PATH'))).toBe(
      true,
    );
  });

  it('packs routes with identical attributes into one UPDATE and splits routes with differing attributes', () => {
    const cfg = makeBaseConfig({
      routerA: {
        routes: [
          { id: 'r1', prefix: '203.0.113.0/24', origin: 0, med: 10, communities: [makeCommunity(65001, 1)] },
          { id: 'r2', prefix: '203.0.114.0/24', origin: 0, med: 10, communities: [makeCommunity(65001, 1)] },
          { id: 'r3', prefix: '203.0.115.0/24', origin: 0, med: 99, communities: [makeCommunity(65001, 1)] },
        ],
      },
      routerB: { routes: [] },
    });

    const trace = buildSession(cfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
    ]);

    const updates = bgpSteps(trace.steps).filter(
      (s) => s.bgpMessage?.type === 'update' && isEndOfRib(s.bgpMessage) === null,
    );
    expect(updates).toHaveLength(2);
    expect(updates[0].summary).toBe('UPDATE +203.0.113.0/24, 203.0.114.0/24');
    expect(updates[1].summary).toBe('UPDATE +203.0.115.0/24');
  });

  it('handles Bad Peer AS (NOTIFICATION 2/2), Hold Timer Expiry (4/0), and Admin Shutdown (6/2)', () => {
    // 1. Bad Peer AS
    const badAsCfg = makeBaseConfig({
      routerA: { asn: 65001 },
      routerB: { asn: 65002, expectedPeerAs: 65999 },
    });
    const badAsTrace = buildSession(badAsCfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
    ]);
    const badAsBgp = bgpSteps(badAsTrace.steps);
    expect(badAsBgp.map((s) => s.summary)).toEqual([
      'OPEN (AS 65001, Hold 90s, 3 caps)',
      'NOTIFICATION (2/2)',
    ]);
    expect(badAsTrace.finalState.phase).toBe('Closed');
    expect(badAsTrace.steps.some((s) => s.summary === 'TCP FIN+ACK')).toBe(true);

    // 2. Hold Timer Expired
    const holdCfg = makeBaseConfig({
      routerA: { holdTime: 90, routes: [] },
      routerB: { holdTime: 90, routes: [] },
    });
    const holdTrace = buildSession(holdCfg, [
      { type: 'establish' },
      { type: 'holdTimerExpires', router: 'A' },
    ]);
    const holdBgp = bgpSteps(holdTrace.steps);
    const notifHold = holdBgp[holdBgp.length - 1];
    expect(notifHold.summary).toBe('NOTIFICATION (4/0)');
    // Verify timestamp is Hold Time (90s) after last BGP message received by A (B's KEEPALIVE)
    const lastFromB = holdBgp.filter((s) => s.from === 'B').at(-1)!;
    const lastFromABeforeHold = holdBgp.filter((s) => s.from === 'A' && s.t <= lastFromB.t).at(-1)!;
    expect(notifHold.t - lastFromB.t).toBe(90_000);
    // Verify periodic KEEPALIVEs are spaced at 30s intervals from A's last TX time, strictly before expiry
    const periodicKas = holdBgp.filter(
      (s) => s.from === 'A' && s.summary === 'KEEPALIVE' && s.t > lastFromB.t,
    );
    expect(periodicKas.map((k) => k.t - lastFromABeforeHold.t)).toEqual([30_000, 60_000, 90_000]);
    expect(periodicKas.every((k) => k.t < notifHold.t)).toBe(true);
    expect(holdTrace.finalState.phase).toBe('Closed');

    // 3. Administrative Shutdown
    const shutTrace = buildSession(holdCfg, [
      { type: 'establish' },
      { type: 'adminShutdown', router: 'B' },
    ]);
    const shutNotif = bgpSteps(shutTrace.steps).at(-1)!;
    expect(shutNotif.from).toBe('B');
    expect(shutNotif.summary).toBe('NOTIFICATION (6/2)');
    expect(shutTrace.finalState.phase).toBe('Closed');
  });

  it('keeps session Established and records a note when holdTimerExpires fires with negotiated Hold Time 0', () => {
    const cfg = makeBaseConfig({
      routerA: { holdTime: 0, routes: [] },
      routerB: { holdTime: 90, routes: [] },
    });
    const trace = buildSession(cfg, [
      { type: 'establish' },
      { type: 'holdTimerExpires', router: 'A' },
    ]);

    expect(trace.finalState.negotiatedHoldTime).toBe(0);
    expect(trace.finalState.keepaliveInterval).toBe(0);
    expect(trace.finalState.phase).toBe('Established');
    expect(bgpSteps(trace.steps).some((s) => s.bgpMessage?.type === 'notification')).toBe(false);
    expect(trace.notes).toHaveLength(1);
    expect(trace.notes[0]).toContain('Hold Time is 0s');
    expect(trace.notes[0]).toContain('RFC 4271 §4.2');
  });

  it('explains accurately in OPEN when ASN > 65535 and fourOctetAs capability is disabled', () => {
    const cfg = makeBaseConfig({
      routerA: { asn: 65551, capabilities: { fourOctetAs: false }, routes: [] },
      routerB: { asn: 65552, capabilities: { fourOctetAs: false }, routes: [] },
    });
    const trace = buildSession(cfg, [{ type: 'establish' }]);
    const [openA, openB] = bgpSteps(trace.steps);

    expect(
      openA.explanations.some(
        (e) => e.includes('4-octet AS capability is disabled') && e.includes('not carried in Capability 65'),
      ),
    ).toBe(true);
    expect(
      openB.explanations.some(
        (e) => e.includes('4-octet AS capability is disabled') && e.includes('not carried in Capability 65'),
      ),
    ).toBe(true);
  });

  it('uses configured ipv4NextHop or falls back to Router ID with clear explanation for IPv4 routes over IPv6 peering', () => {
    const fallbackCfg = makeBaseConfig({
      routerA: {
        peeringAddress: '2001:db8::1',
        routerId: '192.0.2.10',
        routes: [{ id: 'v4', prefix: '203.0.113.0/24', origin: 0 }],
      },
      routerB: { peeringAddress: '2001:db8::2', routes: [] },
    });
    const fallbackTrace = buildSession(fallbackCfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
    ]);
    const fallbackAdv = bgpSteps(fallbackTrace.steps).find((s) => s.summary === 'UPDATE +203.0.113.0/24')!;
    expect(
      fallbackAdv.bgpMessage?.type === 'update' &&
        fallbackAdv.bgpMessage.pathAttributes.find((a) => a.kind === 'nextHop'),
    ).toEqual({ kind: 'nextHop', nextHop: '192.0.2.10' });
    expect(
      fallbackAdv.explanations.some(
        (e) => e.includes('IPv6 peering session') && e.includes('falls back to') && e.includes('Router ID'),
      ),
    ).toBe(true);

    const configuredCfg = makeBaseConfig({
      routerA: {
        peeringAddress: '2001:db8::1',
        routerId: '192.0.2.10',
        ipv4NextHop: '198.51.100.1',
        routes: [{ id: 'v4', prefix: '203.0.113.0/24', origin: 0 }],
      },
      routerB: { peeringAddress: '2001:db8::2', routes: [] },
    });
    const configuredTrace = buildSession(configuredCfg, [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
    ]);
    const configuredAdv = bgpSteps(configuredTrace.steps).find((s) => s.summary === 'UPDATE +203.0.113.0/24')!;
    expect(
      configuredAdv.bgpMessage?.type === 'update' &&
        configuredAdv.bgpMessage.pathAttributes.find((a) => a.kind === 'nextHop'),
    ).toEqual({ kind: 'nextHop', nextHop: '198.51.100.1' });
    expect(
      configuredAdv.explanations.some(
        (e) => e.includes('IPv6 peering session') && e.includes('configured ipv4NextHop 198.51.100.1'),
      ),
    ).toBe(true);
  });

  it('records an omission when withdraw targets an inactive address family', () => {
    const cfg = makeBaseConfig({
      routerA: {
        capabilities: { mpIpv4Unicast: true, mpIpv6Unicast: true },
        routes: [{ id: 'v6', prefix: '2001:db8:1::/48', origin: 0 }],
      },
      routerB: {
        capabilities: { mpIpv4Unicast: true, mpIpv6Unicast: false },
        routes: [],
      },
    });
    const trace = buildSession(cfg, [
      { type: 'establish' },
      { type: 'withdraw', router: 'A', routeIds: ['v6'] },
    ]);
    expect(trace.omissions).toHaveLength(1);
    expect(trace.omissions[0].prefix).toBe('2001:db8:1::/48');
    expect(trace.omissions[0].reason).toContain('did not withdraw');
    expect(trace.omissions[0].reason).toContain('MP IPv6 Unicast');
  });
});
