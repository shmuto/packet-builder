import { describe, expect, it } from 'vitest';
import { formatSupportedLayersList } from './layerMeta';

describe('formatSupportedLayersList', () => {
  it('generates the header protocol list in stack-toolbar order', () => {
    expect(formatSupportedLayersList()).toBe(
      'Ethernet II, VLAN (802.1Q), ARP, IPv4, IPv6, ICMP, ICMPv6, GRE, UDP, TCP, VXLAN, and BGP-4',
    );
  });
});
