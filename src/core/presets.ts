import { encodeUtf8 } from './bytes';
import { createDefaultARP } from './layers/arp';
import { createDefaultBGP } from './layers/bgp';
import { createDefaultEthernet } from './layers/ethernet';
import { createDefaultGRE } from './layers/gre';
import { createDefaultICMP } from './layers/icmp';
import { createDefaultICMPv6 } from './layers/icmpv6';
import { createDefaultIPv4 } from './layers/ipv4';
import { createDefaultIPv6 } from './layers/ipv6';
import { createDefaultTCP } from './layers/tcp';
import type { Layer } from './layers/types';
import { manualValue } from './layers/types';
import { createDefaultUDP } from './layers/udp';
import { createDefaultVLAN } from './layers/vlan';
import { createDefaultVXLAN } from './layers/vxlan';

export {
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
};

export type PresetId =
  | 'udp'
  | 'udp-ipv6'
  | 'tcp-syn'
  | 'icmp-echo'
  | 'icmpv6-echo'
  | 'arp-request'
  | 'vlan-udp'
  | 'gre-ipv4'
  | 'vxlan'
  | 'bgp-open'
  | 'igmp-router-alert';

export interface PacketPreset {
  readonly id: PresetId;
  readonly name: string;
  readonly description: string;
  readonly layers: readonly Layer[];
  readonly payloadMode?: 'text' | 'hex';
  readonly payloadText: string;
  readonly payloadBytes: Uint8Array;
}

/** Creates the built-in packet presets for quick exploration */
export function createPresets(): readonly PacketPreset[] {
  const udpText = 'Hello, tsumiki!!!!';
  const udpIpv6Text = 'Hello';
  const icmpText = 'tsumiki-icmp-ping!';
  const icmpv6Text = 'ping';
  const vlanUdpText = 'Hello, VLAN!!!';
  const grePingText = 'gre-ping';

  return [
    {
      id: 'udp',
      name: 'UDP Packet',
      description: 'Standard Ethernet II + IPv4 + UDP frame with payload',
      layers: [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()],
      payloadText: udpText,
      payloadBytes: encodeUtf8(udpText),
    },
    {
      id: 'udp-ipv6',
      name: 'IPv6 UDP',
      description: 'Ethernet II + IPv6 (RFC 8200) + UDP frame with IPv6 pseudo-header checksum',
      layers: [createDefaultEthernet(), createDefaultIPv6(), createDefaultUDP()],
      payloadText: udpIpv6Text,
      payloadBytes: encodeUtf8(udpIpv6Text),
    },
    {
      id: 'tcp-syn',
      name: 'TCP SYN',
      description:
        'Initial TCP SYN packet with Linux-style options (MSS 1460, SACK-Permitted, Timestamps, NOP, Window Scale 7)',
      layers: [
        createDefaultEthernet(),
        createDefaultIPv4(),
        {
          ...createDefaultTCP(),
          options: [
            { kind: 'mss', mss: 1460 },
            { kind: 'sackPermitted' },
            { kind: 'timestamps', tsVal: 1000000, tsEcr: 0 },
            { kind: 'nop' },
            { kind: 'windowScale', shiftCount: 7 },
          ],
        },
      ],
      payloadText: '',
      payloadBytes: new Uint8Array(0),
    },
    {
      id: 'icmp-echo',
      name: 'ICMP Ping',
      description: 'ICMP Echo Request packet (Type 8, Code 0)',
      layers: [createDefaultEthernet(), createDefaultIPv4(), createDefaultICMP()],
      payloadText: icmpText,
      payloadBytes: encodeUtf8(icmpText),
    },
    {
      id: 'icmpv6-echo',
      name: 'IPv6 Ping',
      description: 'Ethernet II + IPv6 + ICMPv6 Echo Request (Type 128, Code 0, RFC 4443)',
      layers: [createDefaultEthernet(), createDefaultIPv6(), createDefaultICMPv6()],
      payloadText: icmpv6Text,
      payloadBytes: encodeUtf8(icmpv6Text),
    },
    {
      id: 'arp-request',
      name: 'ARP Request',
      description: 'Broadcast Ethernet II + ARP Request (who-has 192.168.0.2)',
      layers: [
        { ...createDefaultEthernet(), dstMac: 'ff:ff:ff:ff:ff:ff' },
        createDefaultARP(),
      ],
      payloadText: '',
      payloadBytes: new Uint8Array(0),
    },
    {
      id: 'vlan-udp',
      name: 'VLAN UDP',
      description: 'Ethernet II + IEEE 802.1Q VLAN (VID 100) + IPv4 + UDP frame',
      layers: [
        createDefaultEthernet(),
        createDefaultVLAN(),
        createDefaultIPv4(),
        createDefaultUDP(),
      ],
      payloadText: vlanUdpText,
      payloadBytes: encodeUtf8(vlanUdpText),
    },
    {
      id: 'gre-ipv4',
      name: 'GRE Tunnel',
      description: 'Ethernet II + Outer IPv4 (Proto 47) + GRE + Inner IPv4 + ICMP Echo Request',
      layers: [
        createDefaultEthernet(),
        {
          ...createDefaultIPv4(),
          srcIp: '198.51.100.1',
          dstIp: '198.51.100.2',
        },
        createDefaultGRE(),
        {
          ...createDefaultIPv4(),
          identification: 0x5678,
          srcIp: '10.0.1.1',
          dstIp: '10.0.2.1',
        },
        createDefaultICMP(),
      ],
      payloadText: grePingText,
      payloadBytes: encodeUtf8(grePingText),
    },
    {
      id: 'vxlan',
      name: 'VXLAN Overlay',
      description:
        'Outer Ethernet II + IPv4 + UDP (4789) + VXLAN (VNI 100) + Inner Ethernet II + ARP Request',
      layers: [
        createDefaultEthernet(),
        {
          ...createDefaultIPv4(),
          srcIp: '198.51.100.1',
          dstIp: '198.51.100.2',
        },
        {
          ...createDefaultUDP(),
          srcPort: 49152,
          dstPort: 4789,
        },
        createDefaultVXLAN(),
        { ...createDefaultEthernet(), dstMac: 'ff:ff:ff:ff:ff:ff' },
        createDefaultARP(),
      ],
      payloadText: '',
      payloadBytes: new Uint8Array(0),
    },
    {
      id: 'bgp-open',
      name: 'BGP OPEN',
      description: 'Ethernet II + IPv4 + TCP (port 179) + BGP-4 OPEN message (RFC 4271)',
      layers: [
        createDefaultEthernet(),
        createDefaultIPv4(),
        {
          ...createDefaultTCP(),
          dstPort: 179,
          ackNumber: 1,
          flags: {
            cwr: false,
            ece: false,
            urg: false,
            ack: true,
            psh: true,
            rst: false,
            syn: false,
            fin: false,
          },
        },
        createDefaultBGP(),
      ],
      payloadText: '',
      payloadBytes: new Uint8Array(0),
    },
    {
      id: 'igmp-router-alert',
      name: 'IGMPv2 (Router Alert)',
      description:
        'Ethernet II + IPv4 (TTL 1, Router Alert option 94 04 00 00, Protocol 2) + IGMPv2 General Query payload',
      layers: [
        { ...createDefaultEthernet(), dstMac: '01:00:5e:00:00:01' },
        {
          ...createDefaultIPv4(),
          ttl: 1,
          protocol: manualValue(2),
          dstIp: '224.0.0.1',
          options: [{ kind: 'routerAlert', value: 0 }],
        },
      ],
      payloadMode: 'hex',
      payloadText: '',
      // IGMPv2 General Membership Query (RFC 2236 §2): Type 0x11, Max Resp Time 100 (0x64), Checksum 0xee9b, Group 0.0.0.0
      payloadBytes: new Uint8Array([0x11, 0x64, 0xee, 0x9b, 0x00, 0x00, 0x00, 0x00]),
    },
  ];
}
