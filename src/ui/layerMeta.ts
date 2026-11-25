import type { Layer, LayerType } from '../core/layers/types';
import {
  createDefaultARP,
  createDefaultEthernet,
  createDefaultICMP,
  createDefaultIPv4,
  createDefaultTCP,
  createDefaultUDP,
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
  icmp: {
    type: 'icmp',
    name: 'ICMP',
    shortName: 'ICMP',
    rfc: 'RFC 792',
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
};

export const ADDABLE_LAYER_TYPES: readonly LayerType[] = [
  'ethernet',
  'arp',
  'ipv4',
  'icmp',
  'udp',
  'tcp',
];

export function createLayerByType(type: LayerType): Layer {
  switch (type) {
    case 'ethernet':
      return createDefaultEthernet();
    case 'arp':
      return createDefaultARP();
    case 'ipv4':
      return createDefaultIPv4();
    case 'icmp':
      return createDefaultICMP();
    case 'udp':
      return createDefaultUDP();
    case 'tcp':
      return createDefaultTCP();
  }
}
