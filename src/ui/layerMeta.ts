import type { Layer, LayerType } from '../core/layers/types';
import {
  createDefaultARP,
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultGRE,
  createDefaultICMP,
  createDefaultICMPv6,
  createDefaultIPv4,
  createDefaultIPv6,
  createDefaultTCP,
  createDefaultUDP,
  createDefaultVLAN,
  createDefaultVXLAN,
} from '../core/presets';

export interface LayerMetaInfo {
  readonly type: LayerType;
  readonly name: string;
  readonly shortName: string;
  readonly rfc: string;
  readonly osiLabel: string;
}

export const LAYER_META: Readonly<Record<LayerType, LayerMetaInfo>> = {
  ethernet: {
    type: 'ethernet',
    name: 'Ethernet II',
    shortName: 'ETH',
    rfc: 'RFC 894 / IEEE 802.3',
    osiLabel: 'L2',
  },
  vlan: {
    type: 'vlan',
    name: 'VLAN (802.1Q)',
    shortName: 'VLAN',
    rfc: 'IEEE 802.1Q',
    osiLabel: 'L2',
  },
  arp: {
    type: 'arp',
    name: 'ARP',
    shortName: 'ARP',
    rfc: 'RFC 826',
    osiLabel: 'L2.5',
  },
  ipv4: {
    type: 'ipv4',
    name: 'IPv4',
    shortName: 'IPv4',
    rfc: 'RFC 791',
    osiLabel: 'L3',
  },
  ipv6: {
    type: 'ipv6',
    name: 'IPv6',
    shortName: 'IPv6',
    rfc: 'RFC 8200',
    osiLabel: 'L3',
  },
  icmp: {
    type: 'icmp',
    name: 'ICMP',
    shortName: 'ICMP',
    rfc: 'RFC 792',
    osiLabel: 'L3',
  },
  icmpv6: {
    type: 'icmpv6',
    name: 'ICMPv6',
    shortName: 'ICMPv6',
    rfc: 'RFC 4443',
    osiLabel: 'L3',
  },
  gre: {
    type: 'gre',
    name: 'GRE',
    shortName: 'GRE',
    rfc: 'RFC 2784 / 2890',
    osiLabel: 'L3',
  },
  udp: {
    type: 'udp',
    name: 'UDP',
    shortName: 'UDP',
    rfc: 'RFC 768',
    osiLabel: 'L4',
  },
  tcp: {
    type: 'tcp',
    name: 'TCP',
    shortName: 'TCP',
    rfc: 'RFC 9293',
    osiLabel: 'L4',
  },
  vxlan: {
    type: 'vxlan',
    name: 'VXLAN',
    shortName: 'VXLAN',
    rfc: 'RFC 7348',
    osiLabel: 'L4.5',
  },
  bgp: {
    type: 'bgp',
    name: 'BGP-4',
    shortName: 'BGP',
    rfc: 'RFC 4271',
    osiLabel: 'L7',
  },
};

export const ADDABLE_LAYER_TYPES: readonly LayerType[] = [
  'ethernet',
  'vlan',
  'arp',
  'ipv4',
  'ipv6',
  'icmp',
  'icmpv6',
  'gre',
  'udp',
  'tcp',
  'vxlan',
  'bgp',
];

export function createLayerByType(type: LayerType): Layer {
  switch (type) {
    case 'ethernet':
      return createDefaultEthernet();
    case 'vlan':
      return createDefaultVLAN();
    case 'arp':
      return createDefaultARP();
    case 'ipv4':
      return createDefaultIPv4();
    case 'ipv6':
      return createDefaultIPv6();
    case 'icmp':
      return createDefaultICMP();
    case 'icmpv6':
      return createDefaultICMPv6();
    case 'gre':
      return createDefaultGRE();
    case 'udp':
      return createDefaultUDP();
    case 'tcp':
      return createDefaultTCP();
    case 'vxlan':
      return createDefaultVXLAN();
    case 'bgp':
      return createDefaultBGP();
  }
}
