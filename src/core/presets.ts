import { encodeUtf8 } from './bytes';
import type {
  ARPLayer,
  BGPLayer,
  EthernetLayer,
  GRELayer,
  ICMPLayer,
  ICMPv6Layer,
  IPv4Layer,
  IPv6Layer,
  Layer,
  TCPLayer,
  UDPLayer,
  VLANLayer,
  VXLANLayer,
} from './layers/types';
import { autoValue, manualValue } from './layers/types';

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

export function createDefaultEthernet(): EthernetLayer {
  return {
    type: 'ethernet',
    dstMac: '00:11:22:33:44:55',
    srcMac: '66:77:88:99:aa:bb',
    etherType: autoValue(),
  };
}

/** Creates a default IEEE 802.1Q VLAN tag (PCP 0, DEI 0, VID 100). */
export function createDefaultVLAN(): VLANLayer {
  return {
    type: 'vlan',
    pcp: 0,
    dei: false,
    vid: 100,
    etherType: autoValue(),
  };
}

export function createDefaultARP(): ARPLayer {
  return {
    type: 'arp',
    hardwareType: autoValue(),
    protocolType: autoValue(),
    hardwareLength: autoValue(),
    protocolLength: autoValue(),
    operation: 1,
    senderMac: '66:77:88:99:aa:bb',
    senderIp: '192.168.0.1',
    targetMac: '00:00:00:00:00:00',
    targetIp: '192.168.0.2',
  };
}

export function createDefaultIPv4(): IPv4Layer {
  return {
    type: 'ipv4',
    ihl: autoValue(),
    tos: 0,
    totalLength: autoValue(),
    identification: 0x1234,
    flags: { reserved: false, df: true, mf: false },
    fragmentOffset: 0,
    ttl: 64,
    protocol: autoValue(),
    headerChecksum: autoValue(),
    srcIp: '192.168.0.1',
    dstIp: '192.168.0.2',
    options: [],
  };
}

/** Creates a default IPv6 header using the RFC 3849 documentation prefix (2001:db8::/32). */
export function createDefaultIPv6(): IPv6Layer {
  return {
    type: 'ipv6',
    trafficClass: 0,
    flowLabel: 0,
    payloadLength: autoValue(),
    nextHeader: autoValue(),
    hopLimit: 64,
    srcIp: '2001:db8::1',
    dstIp: '2001:db8::2',
  };
}

export function createDefaultUDP(): UDPLayer {
  return {
    type: 'udp',
    srcPort: 12345,
    dstPort: 8080,
    length: autoValue(),
    checksum: autoValue(),
  };
}

export function createDefaultTCP(): TCPLayer {
  return {
    type: 'tcp',
    srcPort: 54321,
    dstPort: 443,
    seqNumber: 1000,
    ackNumber: 0,
    dataOffset: autoValue(),
    flags: {
      cwr: false,
      ece: false,
      urg: false,
      ack: false,
      psh: false,
      rst: false,
      syn: true,
      fin: false,
    },
    windowSize: 65535,
    checksum: autoValue(),
    urgentPointer: 0,
    options: [],
  };
}

export function createDefaultICMP(): ICMPLayer {
  return {
    type: 'icmp',
    icmpType: 8,
    code: 0,
    checksum: autoValue(),
    identifier: 1,
    sequenceNumber: 1,
  };
}

/** Creates a default ICMPv6 Echo Request header (Type 128, Code 0, RFC 4443 §4.1). */
export function createDefaultICMPv6(): ICMPv6Layer {
  return {
    type: 'icmpv6',
    icmpType: 128,
    code: 0,
    checksum: autoValue(),
    rest: {
      kind: 'echo',
      identifier: 1,
      sequence: 1,
    },
  };
}

/** Creates a default GRE header (4-byte base header, Version 0, auto Protocol Type, RFC 2784). */
export function createDefaultGRE(): GRELayer {
  return {
    type: 'gre',
    checksumPresent: false,
    keyPresent: false,
    sequencePresent: false,
    version: autoValue(),
    protocolType: autoValue(),
    checksum: autoValue(),
    key: 0,
    sequenceNumber: 0,
  };
}

/** Creates a default VXLAN header (I-flag auto 0x08, VNI 100, reserved fields 0, RFC 7348 §5). */
export function createDefaultVXLAN(): VXLANLayer {
  return {
    type: 'vxlan',
    flags: autoValue(),
    vni: 100,
    reserved1: 0,
    reserved2: 0,
  };
}

export function createDefaultBGP(): BGPLayer {
  return {
    type: 'bgp',
    bgpType: 1,
    marker: autoValue(),
    length: autoValue(),
    version: autoValue(),
    myAs: 65001,
    holdTime: 180,
    bgpIdentifier: '192.168.0.1',
    optParamLength: autoValue(),
    withdrawnRoutesLength: autoValue(),
    totalPathAttrLength: autoValue(),
    errorCode: 6,
    errorSubcode: 4,
  };
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
