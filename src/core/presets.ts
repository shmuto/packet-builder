import { encodeUtf8 } from './bytes';
import type {
  ARPLayer,
  EthernetLayer,
  ICMPLayer,
  IPv4Layer,
  Layer,
  TCPLayer,
  UDPLayer,
} from './layers/types';
import { autoValue } from './layers/types';

export type PresetId = 'udp' | 'tcp-syn' | 'icmp-echo' | 'arp-request';

export interface PacketPreset {
  readonly id: PresetId;
  readonly name: string;
  readonly description: string;
  readonly layers: readonly Layer[];
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

/** Creates the built-in packet presets for quick exploration */
export function createPresets(): readonly PacketPreset[] {
  const udpText = 'Hello, tsumiki!!!!';
  const icmpText = 'tsumiki-icmp-ping!';

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
      id: 'tcp-syn',
      name: 'TCP SYN',
      description: 'Initial TCP SYN packet of a 3-way handshake',
      layers: [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
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
  ];
}
