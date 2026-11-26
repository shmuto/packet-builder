import { makeCommunity } from '../bgp';
import type { SessionScenario } from './types';

export const EBGP_IPV4_BASIC_SCENARIO: SessionScenario = {
  id: 'ebgp-ipv4-basic',
  title: 'eBGP IPv4 Basic Session',
  description:
    'Two routers in different ASes (AS 65001 and AS 65002) establish an eBGP session, exchange one IPv4 /24 prefix each, send End-of-RIB markers, and then R1 withdraws its prefix.',
  config: {
    baseTimestampMs: 1_700_000_000_000,
    routerA: {
      name: 'R1',
      asn: 65001,
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
          id: 'r1-v4',
          prefix: '203.0.113.0/24',
          origin: 0,
          med: 50,
          communities: [makeCommunity(65001, 100)],
        },
      ],
    },
    routerB: {
      name: 'R2',
      asn: 65002,
      routerId: '192.0.2.2',
      holdTime: 90,
      mac: '00:00:5e:00:53:02',
      peeringAddress: '192.0.2.2',
      capabilities: {
        mpIpv4Unicast: true,
        mpIpv6Unicast: false,
        routeRefresh: true,
        fourOctetAs: true,
        gracefulRestart: false,
      },
      routes: [
        {
          id: 'r2-v4',
          prefix: '198.51.100.0/24',
          origin: 0,
        },
      ],
    },
  },
  events: [
    { type: 'establish' },
    { type: 'advertise', router: 'A' },
    { type: 'advertise', router: 'B' },
    { type: 'withdraw', router: 'A', routeIds: ['r1-v4'] },
  ],
};

export const BUILTIN_SCENARIOS: readonly SessionScenario[] = [EBGP_IPV4_BASIC_SCENARIO];

export function getBuiltinScenario(id: string): SessionScenario | undefined {
  return BUILTIN_SCENARIOS.find((s) => s.id === id);
}
