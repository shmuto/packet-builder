/**
 * Independent dissector verification using Wireshark's `tshark`.
 *
 * Verified against: TShark (Wireshark) 4.2.2 (Ubuntu 24.04 / ubuntu-latest).
 * Field names verified via `tshark -G fields`:
 *   - frame.number
 *   - bgp.type
 *   - bgp.open.myas
 *   - bgp.open.holdtime
 *   - bgp.open.identifier
 *   - bgp.cap.type
 *   - bgp.update.path_attribute.type_code
 *   - bgp.update.path_attribute.origin
 *   - bgp.update.path_attribute.next_hop
 *   - bgp.update.path_attribute.local_pref
 *   - bgp.nlri_prefix
 *   - bgp.withdrawn_prefix
 *   - bgp.mp_reach_nlri_ipv6_prefix
 *   - bgp.mp_unreach_nlri_ipv6_prefix
 *   - bgp.notify.major_error
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'vite';

const EXPECTED_BGP_TYPE_CODE = {
  open: '1',
  update: '2',
  notification: '3',
  keepalive: '4',
  routeRefresh: '5',
};

const ATTR_KIND_TO_CODE = {
  origin: '1',
  asPath: '2',
  nextHop: '3',
  med: '4',
  localPref: '5',
  atomicAggregate: '6',
  aggregator: '7',
  communities: '8',
  mpReachNlri: '14',
  mpUnreachNlri: '15',
  as4Path: '17',
  as4Aggregator: '18',
  largeCommunities: '32',
};

const CAP_KIND_TO_CODE = {
  mp: '1',
  routeRefresh: '2',
  gracefulRestart: '64',
  fourOctetAs: '65',
  addPath: '69',
  enhancedRouteRefresh: '70',
};

function runTshark(args) {
  return execFileSync('tshark', args, { encoding: 'utf8' });
}

function assertEqual(actual, expected, context) {
  if (actual !== expected) {
    throw new Error(`${context}: expected "${expected}", got "${actual}"`);
  }
}

function stripMask(cidr) {
  const slash = cidr.indexOf('/');
  return slash === -1 ? cidr : cidr.slice(0, slash);
}

function verifyScenarioWithTshark(name, trace, pcapBytes, workDir) {
  const pcapPath = join(workDir, `${name}.pcap`);
  writeFileSync(pcapPath, pcapBytes);

  // 1. Check for any expert-info errors (including IPv4 and TCP checksum validation!)
  const expertOut = runTshark([
    '-r',
    pcapPath,
    '-q',
    '-o',
    'ip.check_checksum:TRUE',
    '-o',
    'tcp.check_checksum:TRUE',
    '-z',
    'expert,error',
  ]);
  const hasErrorsSection = /^Errors\s+\(\d+\)/m.test(expertOut);
  if (hasErrorsSection) {
    throw new Error(
      `[${name}] tshark reported expert-info errors:\n${expertOut}`,
    );
  }

  // 2. Dissect every BGP frame and compare against the SessionTrace
  const fields = [
    'frame.number',
    'bgp.type',
    'bgp.open.myas',
    'bgp.open.holdtime',
    'bgp.open.identifier',
    'bgp.cap.type',
    'bgp.update.path_attribute.type_code',
    'bgp.update.path_attribute.origin',
    'bgp.update.path_attribute.next_hop',
    'bgp.update.path_attribute.multi_exit_disc',
    'bgp.update.path_attribute.local_pref',
    'bgp.update.path_attribute.as_path_segment.as2',
    'bgp.update.path_attribute.as_path_segment.as4',
    'bgp.nlri_prefix',
    'bgp.withdrawn_prefix',
    'bgp.mp_reach_nlri_ipv6_prefix',
    'bgp.mp_unreach_nlri_ipv6_prefix',
    'bgp.notify.major_error',
    'bgp.notify.minor_error',
    'bgp.notify.minor_error_open',
    'bgp.notify.minor_error_update',
    'bgp.notify.minor_error_expired',
    'bgp.notify.minor_error_state',
    'bgp.notify.minor_error_cease',
    'bgp.notify.minor_error_route_refresh',
  ];

  const NOTIFY_MINOR_FIELD_BY_MAJOR = {
    1: 'bgp.notify.minor_error',
    2: 'bgp.notify.minor_error_open',
    3: 'bgp.notify.minor_error_update',
    4: 'bgp.notify.minor_error_expired',
    5: 'bgp.notify.minor_error_state',
    6: 'bgp.notify.minor_error_cease',
    7: 'bgp.notify.minor_error_route_refresh',
  };

  const tsharkArgs = [
    '-r',
    pcapPath,
    '-Y',
    'bgp',
    '-o',
    'ip.check_checksum:TRUE',
    '-o',
    'tcp.check_checksum:TRUE',
    '-T',
    'fields',
    ...fields.flatMap((f) => ['-e', f]),
  ];

  const rawRows = runTshark(tsharkArgs)
    .trim()
    .split('\n')
    .filter((line) => line.length > 0);

  const expectedBgpSteps = trace.steps.filter((s) => s.kind === 'bgp');
  assertEqual(
    String(rawRows.length),
    String(expectedBgpSteps.length),
    `[${name}] BGP frame count`,
  );

  for (let i = 0; i < expectedBgpSteps.length; i++) {
    const step = expectedBgpSteps[i];
    const msg = step.bgpMessage;
    const cols = rawRows[i].split('\t');
    const row = Object.fromEntries(fields.map((f, idx) => [f, cols[idx] ?? '']));
    const ctxLabel = `[${name}] step #${step.index} (frame ${row['frame.number']}, ${step.summary})`;

    assertEqual(row['bgp.type'], EXPECTED_BGP_TYPE_CODE[msg.type], `${ctxLabel} bgp.type`);

    if (msg.type === 'open') {
      const expectedMyAs = msg.myAsOverride ?? (msg.asn <= 0xffff ? msg.asn : 23456);
      assertEqual(row['bgp.open.myas'], String(expectedMyAs), `${ctxLabel} bgp.open.myas`);
      assertEqual(row['bgp.open.holdtime'], String(msg.holdTime), `${ctxLabel} bgp.open.holdtime`);
      assertEqual(row['bgp.open.identifier'], msg.bgpIdentifier, `${ctxLabel} bgp.open.identifier`);
      const expectedCaps = msg.capabilities
        .map((c) => (c.kind === 'raw' ? String(c.code) : CAP_KIND_TO_CODE[c.kind]))
        .join(',');
      assertEqual(row['bgp.cap.type'], expectedCaps, `${ctxLabel} bgp.cap.type`);
    }

    if (msg.type === 'update') {
      const expectedAttrCodes = msg.pathAttributes
        .map((a) => (a.kind === 'raw' ? String(a.typeCode) : ATTR_KIND_TO_CODE[a.kind]))
        .join(',');
      assertEqual(
        row['bgp.update.path_attribute.type_code'],
        expectedAttrCodes,
        `${ctxLabel} path_attribute.type_code`,
      );

      const originAttr = msg.pathAttributes.find((a) => a.kind === 'origin');
      if (originAttr) {
        assertEqual(
          row['bgp.update.path_attribute.origin'],
          String(originAttr.origin),
          `${ctxLabel} origin`,
        );
      }

      const nhAttr = msg.pathAttributes.find((a) => a.kind === 'nextHop');
      if (nhAttr) {
        assertEqual(
          row['bgp.update.path_attribute.next_hop'],
          nhAttr.nextHop,
          `${ctxLabel} next_hop`,
        );
      }

      const medAttr = msg.pathAttributes.find((a) => a.kind === 'med');
      if (medAttr) {
        assertEqual(
          row['bgp.update.path_attribute.multi_exit_disc'],
          String(medAttr.med),
          `${ctxLabel} multi_exit_disc`,
        );
      }

      const lpAttr = msg.pathAttributes.find((a) => a.kind === 'localPref');
      if (lpAttr) {
        assertEqual(
          row['bgp.update.path_attribute.local_pref'],
          String(lpAttr.localPref),
          `${ctxLabel} local_pref`,
        );
      }

      const asPathAttr = msg.pathAttributes.find((a) => a.kind === 'asPath');
      const as4PathAttr = msg.pathAttributes.find((a) => a.kind === 'as4Path');
      if (asPathAttr || as4PathAttr) {
        const expectedAs2 = [];
        const expectedAs4 = [];
        if (asPathAttr) {
          const allAsns = asPathAttr.segments.flatMap((seg) => seg.asns.map(String));
          if (step.state.fourOctetAsActive) {
            expectedAs4.push(...allAsns);
          } else {
            expectedAs2.push(...allAsns);
          }
        }
        if (as4PathAttr) {
          expectedAs4.push(...as4PathAttr.segments.flatMap((seg) => seg.asns.map(String)));
        }
        assertEqual(
          row['bgp.update.path_attribute.as_path_segment.as2'],
          expectedAs2.join(','),
          `${ctxLabel} as_path_segment.as2`,
        );
        assertEqual(
          row['bgp.update.path_attribute.as_path_segment.as4'],
          expectedAs4.join(','),
          `${ctxLabel} as_path_segment.as4`,
        );
      }

      const expectedNlri = msg.nlri.map((p) => stripMask(p.prefix)).join(',');
      assertEqual(row['bgp.nlri_prefix'], expectedNlri, `${ctxLabel} nlri_prefix`);

      const expectedWithdrawn = msg.withdrawnRoutes.map((p) => stripMask(p.prefix)).join(',');
      assertEqual(row['bgp.withdrawn_prefix'], expectedWithdrawn, `${ctxLabel} withdrawn_prefix`);

      const mpReach = msg.pathAttributes.find((a) => a.kind === 'mpReachNlri');
      if (mpReach && mpReach.afi === 2) {
        const expectedV6 = mpReach.nlri.map((p) => stripMask(p.prefix)).join(',');
        assertEqual(
          row['bgp.mp_reach_nlri_ipv6_prefix'],
          expectedV6,
          `${ctxLabel} mp_reach_nlri_ipv6_prefix`,
        );
      }

      const mpUnreach = msg.pathAttributes.find((a) => a.kind === 'mpUnreachNlri');
      if (mpUnreach && mpUnreach.afi === 2) {
        const expectedV6W = mpUnreach.withdrawnRoutes.map((p) => stripMask(p.prefix)).join(',');
        assertEqual(
          row['bgp.mp_unreach_nlri_ipv6_prefix'],
          expectedV6W,
          `${ctxLabel} mp_unreach_nlri_ipv6_prefix`,
        );
      }
    }

    if (msg.type === 'notification') {
      assertEqual(
        row['bgp.notify.major_error'],
        String(msg.errorCode),
        `${ctxLabel} notify.major_error`,
      );
      const minorField = NOTIFY_MINOR_FIELD_BY_MAJOR[msg.errorCode];
      if (minorField) {
        assertEqual(row[minorField], String(msg.errorSubcode), `${ctxLabel} ${minorField}`);
      }
    }
  }

  console.log(
    `PASS [${name}]: ${trace.steps.length} frames (${expectedBgpSteps.length} BGP messages) verified by tshark with 0 expert errors.`,
  );
}

async function main() {
  const versionLine = runTshark(['--version']).split('\n')[0];
  console.log(`Using ${versionLine}`);

  const server = await createServer({
    server: { middlewareMode: true },
    appType: 'custom',
    logLevel: 'silent',
  });

  const workDir = mkdtempSync(join(tmpdir(), 'bgp-oracle-'));
  try {
    const sessionMod = await server.ssrLoadModule('/src/core/session/index.ts');
    const bgpMod = await server.ssrLoadModule('/src/core/bgp/index.ts');

    // 1. All built-in scenarios (includes ebgp-ipv4-basic)
    for (const scenario of sessionMod.BUILTIN_SCENARIOS) {
      const trace = sessionMod.buildSession(scenario.config, scenario.events);
      const pcap = sessionMod.exportSessionPcap(trace);
      verifyScenarioWithTshark(scenario.id, trace, pcap, workDir);
    }

    // 2. Test-only iBGP + IPv6 peering + MP-BGP IPv6 scenario (required by #62)
    const ibgpIpv6Config = {
      baseTimestampMs: 1_700_000_000_000,
      routerA: {
        name: 'IBGP-A',
        asn: 65551,
        routerId: '192.0.2.10',
        holdTime: 90,
        localPref: 150,
        mac: '00:00:5e:00:53:11',
        peeringAddress: '2001:db8::1',
        capabilities: {
          mpIpv4Unicast: true,
          mpIpv6Unicast: true,
          routeRefresh: true,
          fourOctetAs: true,
          gracefulRestart: true,
        },
        routes: [
          {
            id: 'a-v6',
            prefix: '2001:db8:1::/48',
            origin: 0,
            communities: [bgpMod.makeCommunity(65001, 200)],
          },
        ],
      },
      routerB: {
        name: 'IBGP-B',
        asn: 65551,
        routerId: '192.0.2.20',
        holdTime: 60,
        localPref: 100,
        mac: '00:00:5e:00:53:22',
        peeringAddress: '2001:db8::2',
        capabilities: {
          mpIpv4Unicast: true,
          mpIpv6Unicast: true,
          routeRefresh: true,
          fourOctetAs: true,
          gracefulRestart: true,
        },
        routes: [
          {
            id: 'b-v6',
            prefix: '2001:db8:2::/48',
            origin: 0,
          },
        ],
      },
    };
    const ibgpIpv6Events = [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
      { type: 'advertise', router: 'B' },
      { type: 'withdraw', router: 'A', routeIds: ['a-v6'] },
      { type: 'adminShutdown', router: 'B' },
    ];
    const ibgpTrace = sessionMod.buildSession(ibgpIpv6Config, ibgpIpv6Events);
    const ibgpPcap = sessionMod.exportSessionPcap(ibgpTrace);
    verifyScenarioWithTshark('test-ibgp-ipv6', ibgpTrace, ibgpPcap, workDir);

    // 3. Test-only 2-octet/4-octet AS transition (AS_TRANS + AS4_PATH + MED + Hold Timer Expired 4/0)
    const asTransConfig = {
      baseTimestampMs: 1_700_000_000_000,
      routerA: {
        name: 'R1-4B',
        asn: 65551,
        routerId: '192.0.2.1',
        holdTime: 90,
        mac: '00:00:5e:00:53:01',
        peeringAddress: '192.0.2.1',
        capabilities: {
          mpIpv4Unicast: true,
          mpIpv6Unicast: false,
          routeRefresh: true,
          fourOctetAs: true,
          gracefulRestart: false,
        },
        routes: [
          {
            id: 'a-med',
            prefix: '203.0.113.0/24',
            origin: 0,
            med: 50,
          },
        ],
      },
      routerB: {
        name: 'R2-2B',
        asn: 65002,
        routerId: '192.0.2.2',
        holdTime: 90,
        mac: '00:00:5e:00:53:02',
        peeringAddress: '192.0.2.2',
        capabilities: {
          mpIpv4Unicast: true,
          mpIpv6Unicast: false,
          routeRefresh: true,
          fourOctetAs: false,
          gracefulRestart: false,
        },
        routes: [],
      },
    };
    const asTransEvents = [
      { type: 'establish' },
      { type: 'advertise', router: 'A' },
      { type: 'holdTimerExpires', router: 'A' },
    ];
    const asTransTrace = sessionMod.buildSession(asTransConfig, asTransEvents);
    const asTransPcap = sessionMod.exportSessionPcap(asTransTrace);
    verifyScenarioWithTshark('test-as-trans', asTransTrace, asTransPcap, workDir);
  } finally {
    await server.close();
    rmSync(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
