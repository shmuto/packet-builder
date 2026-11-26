import type { LayerType } from './layers/types';

export interface FieldDoc {
  /** 1-2 plain-English sentences explaining what the field does and typical values. */
  readonly summary: string;
  /** Specific RFC or IEEE specification section reference (e.g., "RFC 791 §3.1"). */
  readonly reference: string;
}

/**
 * Exhaustive per-field documentation map keyed by LayerType and FieldSpan.fieldId.
 * Typed with `Record<LayerType, ...>` so adding a new LayerType without field docs
 * fails at compile time.
 */
export const FIELD_DOCS: Readonly<Record<LayerType, Readonly<Record<string, FieldDoc>>>> = {
  ethernet: {
    dstMac: {
      summary:
        '48-bit hardware address of the intended recipient on the local link. Use ff:ff:ff:ff:ff:ff for broadcast frames such as ARP requests.',
      reference: 'IEEE 802.3 §3.2.4',
    },
    srcMac: {
      summary:
        '48-bit hardware address of the interface transmitting the Ethernet frame on the local link.',
      reference: 'IEEE 802.3 §3.2.5',
    },
    etherType: {
      summary:
        '16-bit identifier declaring which protocol is carried inside the Ethernet payload. Common values are 0x0800 (IPv4), 0x86dd (IPv6), and 0x0806 (ARP).',
      reference: 'IEEE 802.3 §3.2.6',
    },
  },

  arp: {
    hardwareType: {
      summary:
        '16-bit code identifying the link-layer hardware type. Value 1 denotes Ethernet.',
      reference: 'RFC 826 "Packet format"',
    },
    protocolType: {
      summary:
        '16-bit code identifying the network-layer protocol being resolved, using EtherType values. Value 0x0800 denotes IPv4.',
      reference: 'RFC 826 "Packet format"',
    },
    hardwareLength: {
      summary:
        'Length in octets of each hardware address in this ARP message. Ethernet MAC addresses are 6 bytes.',
      reference: 'RFC 826 "Packet format"',
    },
    protocolLength: {
      summary:
        'Length in octets of each protocol address in this ARP message. IPv4 addresses are 4 bytes.',
      reference: 'RFC 826 "Packet format"',
    },
    operation: {
      summary:
        'Specifies the ARP action being performed: 1 for Request (asking for a MAC address) and 2 for Reply.',
      reference: 'RFC 826 "Packet format"',
    },
    senderMac: {
      summary:
        'Hardware (MAC) address of the host sending this ARP request or reply.',
      reference: 'RFC 826 "Packet format"',
    },
    senderIp: {
      summary:
        'IPv4 address of the host sending this ARP message.',
      reference: 'RFC 826 "Packet format"',
    },
    targetMac: {
      summary:
        'Hardware (MAC) address of the intended target. Set to 00:00:00:00:00:00 in requests because the address is unknown.',
      reference: 'RFC 826 "Packet format"',
    },
    targetIp: {
      summary:
        'IPv4 address of the host whose MAC address is being queried (in a request) or answered (in a reply).',
      reference: 'RFC 826 "Packet format"',
    },
  },

  ipv4: {
    version: {
      summary:
        '4-bit IP version number identifying the header format. Always 4 for IPv4 packets.',
      reference: 'RFC 791 §3.1',
    },
    ihl: {
      summary:
        'Internet Header Length measured in 32-bit words. The minimum and standard value is 5 (20 bytes, no IPv4 options).',
      reference: 'RFC 791 §3.1',
    },
    tos: {
      summary:
        '8-bit quality-of-service field now split into a 6-bit DSCP priority value and 2-bit ECN congestion indicator. Defaults to 0x00 for best-effort traffic.',
      reference: 'RFC 791 §3.1 / RFC 2474 §3 / RFC 3168 §5',
    },
    totalLength: {
      summary:
        'Total length of the IPv4 packet in bytes, including both the header and payload. Minimum is 20 bytes and maximum is 65,535 bytes.',
      reference: 'RFC 791 §3.1',
    },
    identification: {
      summary:
        '16-bit value assigned by the sender to help receivers group fragments belonging to the same original IPv4 datagram.',
      reference: 'RFC 791 §3.1',
    },
    flags: {
      summary:
        '3-bit fragmentation control field: Reserved (must be 0), DF (Don\'t Fragment), and MF (More Fragments follow).',
      reference: 'RFC 791 §3.1',
    },
    fragmentOffset: {
      summary:
        'Position of this fragment\'s payload relative to the start of the original datagram, measured in 8-byte blocks. Zero for unfragmented packets and initial fragments.',
      reference: 'RFC 791 §3.1',
    },
    ttl: {
      summary:
        'Hop limit decremented by each router; the packet is dropped when it reaches 0 to prevent routing loops. Common initial values are 64 and 128.',
      reference: 'RFC 791 §3.1',
    },
    protocol: {
      summary:
        '8-bit IANA number identifying the next encapsulated protocol in the IPv4 payload. Common values are 1 (ICMP), 4 (IP-in-IP), 6 (TCP), 17 (UDP), and 41 (IPv6).',
      reference: 'RFC 791 §3.1',
    },
    headerChecksum: {
      summary:
        '16-bit one\'s-complement checksum covering only the IPv4 header (not the payload). Routers recompute it whenever TTL changes.',
      reference: 'RFC 791 §3.1',
    },
    srcIp: {
      summary:
        '32-bit IPv4 address of the host that originated the packet.',
      reference: 'RFC 791 §3.1',
    },
    dstIp: {
      summary:
        '32-bit IPv4 address of the final destination host.',
      reference: 'RFC 791 §3.1',
    },
  },

  ipv6: {
    version: {
      summary:
        '4-bit IP version number identifying the header format. Always 6 for IPv6 packets.',
      reference: 'RFC 8200 §3',
    },
    trafficClass: {
      summary:
        '8-bit quality-of-service field split into a 6-bit DSCP priority code and 2-bit ECN congestion indicator. Defaults to 0x00 for best-effort traffic.',
      reference: 'RFC 8200 §3 / RFC 2474 §3 / RFC 3168 §5',
    },
    flowLabel: {
      summary:
        '20-bit label identifying packets belonging to the same flow so routers can apply consistent forwarding or load-balancing. Set to 0 when unused.',
      reference: 'RFC 8200 §3 / RFC 6437 §2',
    },
    payloadLength: {
      summary:
        '16-bit length in bytes of the payload following the 40-byte fixed IPv6 header (including any extension headers). Maximum standard value is 65,535 bytes.',
      reference: 'RFC 8200 §3',
    },
    nextHeader: {
      summary:
        '8-bit IANA protocol number identifying the header immediately following the IPv6 header. Common values are 6 (TCP), 17 (UDP), 4 (IPv4), 41 (IPv6), and 58 (ICMPv6).',
      reference: 'RFC 8200 §3',
    },
    hopLimit: {
      summary:
        'Remaining router hops allowed before the packet is discarded; decremented by 1 at each forwarding node. Common initial value is 64.',
      reference: 'RFC 8200 §3',
    },
    srcIp: {
      summary:
        '128-bit IPv6 address of the packet originator, written in RFC 5952 canonical colon-hexadecimal notation.',
      reference: 'RFC 8200 §3',
    },
    dstIp: {
      summary:
        '128-bit IPv6 address of the intended recipient (or next-hop routing header target).',
      reference: 'RFC 8200 §3',
    },
  },

  icmp: {
    icmpType: {
      summary:
        '8-bit category of the ICMP control or diagnostic message. Common values are 8 (Echo Request / ping) and 0 (Echo Reply).',
      reference: 'RFC 792 "Echo or Echo Reply Message"',
    },
    code: {
      summary:
        '8-bit subtype giving extra context for the ICMP Type. Always 0 for Echo Request and Echo Reply.',
      reference: 'RFC 792 "Echo or Echo Reply Message"',
    },
    checksum: {
      summary:
        '16-bit one\'s-complement checksum calculated over the entire ICMP header and payload to detect corruption.',
      reference: 'RFC 792 "Echo or Echo Reply Message"',
    },
    identifier: {
      summary:
        '16-bit value chosen by the sender (often a process ID) to match Echo Replies back to the originating ping session.',
      reference: 'RFC 792 "Echo or Echo Reply Message"',
    },
    sequenceNumber: {
      summary:
        '16-bit counter incremented for each Echo Request sent in a session so replies can be ordered and packet loss detected.',
      reference: 'RFC 792 "Echo or Echo Reply Message"',
    },
  },

  icmpv6: {
    icmpType: {
      summary:
        '8-bit message category: 0-127 are error messages (such as 2 = Packet Too Big, 4 = Parameter Problem) and 128-255 are informational messages (128 = Echo Request, 129 = Echo Reply).',
      reference: 'RFC 4443 §2.1',
    },
    code: {
      summary:
        '8-bit subtype refining the ICMPv6 Type (for example, 0 for Echo Request/Reply and Packet Too Big, or 0-2 for Parameter Problem).',
      reference: 'RFC 4443 §2.1',
    },
    checksum: {
      summary:
        '16-bit mandatory one\'s-complement checksum covering the 40-byte IPv6 pseudo-header (Next Header 58), the ICMPv6 header, and the message payload.',
      reference: 'RFC 4443 §2.3 / RFC 8200 §8.1',
    },
    identifier: {
      summary:
        '16-bit identifier chosen by the sender to match Echo Replies back to the originating IPv6 ping session.',
      reference: 'RFC 4443 §4.1 / §4.2',
    },
    sequence: {
      summary:
        '16-bit counter incremented for each Echo Request sent in a session to order replies and detect packet loss.',
      reference: 'RFC 4443 §4.1 / §4.2',
    },
    restValue: {
      summary:
        '32-bit type-specific header field: carries the next-hop link MTU for Packet Too Big (Type 2), the byte offset Pointer for Parameter Problem (Type 4), or Unused zero bits for other messages.',
      reference: 'RFC 4443 §2.1 / §3.2 / §3.4',
    },
  },

  udp: {
    srcPort: {
      summary:
        '16-bit port number of the sending process, typically an ephemeral port (49152-65535). May be 0 when no reply is needed.',
      reference: 'RFC 768 "Fields"',
    },
    dstPort: {
      summary:
        '16-bit port number identifying the target service on the destination host, such as 53 (DNS) or 443 (QUIC).',
      reference: 'RFC 768 "Fields"',
    },
    length: {
      summary:
        'Length in bytes of the UDP header (8 bytes) plus its payload. Minimum valid value is 8.',
      reference: 'RFC 768 "Fields"',
    },
    checksum: {
      summary:
        '16-bit checksum over the IPv4/IPv6 pseudo-header, UDP header, and payload. A computed zero is sent as 0xffff; 0x0000 disables the checksum over IPv4 but is invalid over IPv6 where checksums are mandatory.',
      reference: 'RFC 768 "Fields" / RFC 8200 §8.1',
    },
  },

  tcp: {
    srcPort: {
      summary:
        '16-bit port number of the sending endpoint, commonly an ephemeral port (49152-65535) for client connections.',
      reference: 'RFC 9293 §3.1',
    },
    dstPort: {
      summary:
        '16-bit port number of the destination service, such as 80 (HTTP), 179 (BGP), or 443 (HTTPS).',
      reference: 'RFC 9293 §3.1',
    },
    seqNumber: {
      summary:
        '32-bit sequence number of the first payload byte in this segment, or the Initial Sequence Number (ISN) when SYN is set.',
      reference: 'RFC 9293 §3.1',
    },
    ackNumber: {
      summary:
        '32-bit next sequence number the sender expects to receive; meaningful only when the ACK control bit is set.',
      reference: 'RFC 9293 §3.1',
    },
    dataOffset: {
      summary:
        '4-bit TCP header length measured in 32-bit words, marking where payload data begins. Value 5 means a 20-byte header with no options.',
      reference: 'RFC 9293 §3.1',
    },
    reserved: {
      summary:
        '4-bit field reserved for future use; senders must set all four bits to 0.',
      reference: 'RFC 9293 §3.1',
    },
    flags: {
      summary:
        '8 control bits managing connection state and congestion signaling: CWR, ECE, URG, ACK, PSH, RST, SYN, and FIN.',
      reference: 'RFC 9293 §3.1',
    },
    windowSize: {
      summary:
        '16-bit receive buffer space (in bytes, before any Window Scale option) that the sender is currently willing to accept.',
      reference: 'RFC 9293 §3.1',
    },
    checksum: {
      summary:
        '16-bit mandatory checksum covering the IPv4/IPv6 pseudo-header, TCP header, and payload to verify end-to-end integrity.',
      reference: 'RFC 9293 §3.1 / RFC 8200 §8.1',
    },
    urgentPointer: {
      summary:
        '16-bit positive offset from the Sequence Number indicating the end of urgent data; valid only when the URG bit is set.',
      reference: 'RFC 9293 §3.1',
    },
  },

  bgp: {
    marker: {
      summary:
        '16-byte synchronization field that must be set to all ones (0xff × 16) in BGP-4 for message framing compatibility.',
      reference: 'RFC 4271 §4.1',
    },
    length: {
      summary:
        'Total length of the BGP message in bytes, including the 19-byte common header. Standard BGP-4 allows 19 to 4,096 bytes.',
      reference: 'RFC 4271 §4.1',
    },
    bgpType: {
      summary:
        '1-byte code identifying the BGP message type: 1 (OPEN), 2 (UPDATE), 3 (NOTIFICATION), or 4 (KEEPALIVE).',
      reference: 'RFC 4271 §4.1',
    },
    version: {
      summary:
        '1-byte protocol version advertised during session setup. Always 4 for BGP-4.',
      reference: 'RFC 4271 §4.2',
    },
    myAs: {
      summary:
        '16-bit Autonomous System Number (ASN) of the BGP speaker sending the OPEN message (use 23456 when carrying a 4-byte ASN in capabilities).',
      reference: 'RFC 4271 §4.2 / RFC 6793 §3',
    },
    holdTime: {
      summary:
        'Maximum seconds allowed between successive KEEPALIVE or UPDATE messages before tearing down the session. Must be 0 (disabled) or at least 3 (commonly 90 or 180).',
      reference: 'RFC 4271 §4.2',
    },
    bgpIdentifier: {
      summary:
        '32-bit router ID formatted like an IPv4 address that uniquely identifies the BGP speaker within its Autonomous System.',
      reference: 'RFC 4271 §4.2',
    },
    optParamLength: {
      summary:
        '1-byte length of the Optional Parameters (such as Capabilities) following the fixed OPEN header. Zero when no optional parameters are sent.',
      reference: 'RFC 4271 §4.2',
    },
    withdrawnRoutesLength: {
      summary:
        '2-byte length of the Withdrawn Routes section listing IPv4 prefixes being removed from service. Zero when no routes are withdrawn.',
      reference: 'RFC 4271 §4.3',
    },
    totalPathAttrLength: {
      summary:
        '2-byte length of the Path Attributes section (such as ORIGIN, AS_PATH, and NEXT_HOP) describing announced routes.',
      reference: 'RFC 4271 §4.3',
    },
    errorCode: {
      summary:
        '1-byte category explaining why a BGP session is being closed (1-6 in RFC 4271, such as 2 = OPEN Message Error or 4 = Hold Timer Expired; 7 = Route Refresh Error).',
      reference: 'RFC 4271 §4.5 / RFC 7313 §5',
    },
    errorSubcode: {
      summary:
        '1-byte detail code refining the Error Code in a NOTIFICATION message, or 0 for an unspecific error.',
      reference: 'RFC 4271 §4.5',
    },
  },
};

/**
 * Looks up the beginner-friendly summary and specification reference for a header field.
 */
export function getFieldDoc(layerType: LayerType, fieldId: string): FieldDoc | undefined {
  const layerDocs = FIELD_DOCS[layerType];
  return Object.prototype.hasOwnProperty.call(layerDocs, fieldId)
    ? layerDocs[fieldId]
    : undefined;
}
