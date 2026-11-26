import {
  decodeUtf8Strict,
  formatIPv4,
  formatIPv6,
  formatMac,
  readUint16BE,
  readUint32BE,
} from './bytes';
import {
  internetChecksum,
  ipv4PseudoHeaderChecksum,
  ipv6PseudoHeaderChecksum,
} from './checksum';
import {
  ARP_HEADER_LENGTH,
  ARP_HLEN_ETHERNET,
  ARP_HTYPE_ETHERNET,
  ARP_PLEN_IPV4,
  ARP_PTYPE_IPV4,
} from './layers/arp';
import {
  BGP_COMMON_HEADER_LENGTH,
  BGP_PORT,
  BGP_TYPE_KEEPALIVE,
  BGP_TYPE_NOTIFICATION,
  BGP_TYPE_OPEN,
  BGP_TYPE_UPDATE,
  BGP_VERSION_4,
  getBGPHeaderLength,
  isAllFF,
} from './layers/bgp';
import {
  ETHERNET_HEADER_LENGTH,
  ethernetEtherTypeForUpperLayers,
  ETHERTYPE_ARP,
  ETHERTYPE_IPV4,
  ETHERTYPE_IPV6,
  ETHERTYPE_QINQ,
  ETHERTYPE_QINQ_LEGACY,
  ETHERTYPE_VLAN,
} from './layers/ethernet';
import {
  getGREHeaderLength,
  GRE_BASE_HEADER_LENGTH,
  GRE_PROTOCOL_TEB,
  greProtocolTypeForUpperLayer,
} from './layers/gre';
import { ICMP_HEADER_LENGTH } from './layers/icmp';
import {
  ICMPV6_HEADER_LENGTH,
  ICMPV6_TYPE_ECHO_REPLY,
  ICMPV6_TYPE_ECHO_REQUEST,
  IP_PROTOCOL_ICMPV6,
} from './layers/icmpv6';
import {
  IP_PROTOCOL_GRE,
  IP_PROTOCOL_ICMP,
  IP_PROTOCOL_IPIP,
  IP_PROTOCOL_IPV6,
  IP_PROTOCOL_TCP,
  IP_PROTOCOL_UDP,
  IPV4_HEADER_LENGTH,
  IPV4_IHL,
  IPV4_OPT_EOL,
  IPV4_OPT_LSRR,
  IPV4_OPT_NOP,
  IPV4_OPT_ROUTER_ALERT,
  IPV4_OPT_RR,
  IPV4_OPT_SSRR,
  IPV4_OPT_TIMESTAMP,
  IPV4_VERSION,
} from './layers/ipv4';
import { IPV6_HEADER_LENGTH, IPV6_VERSION } from './layers/ipv6';
import {
  TCP_DEFAULT_DATA_OFFSET,
  TCP_HEADER_LENGTH,
  TCP_OPT_EOL,
  TCP_OPT_MSS,
  TCP_OPT_NOP,
  TCP_OPT_SACK,
  TCP_OPT_SACK_PERMITTED,
  TCP_OPT_TIMESTAMPS,
  TCP_OPT_WINDOW_SCALE,
} from './layers/tcp';
import {
  autoValue,
  manualValue,
  type ARPLayer,
  type BGPLayer,
  type BGPMessageType,
  type EthernetLayer,
  type GRELayer,
  type ICMPLayer,
  type ICMPv6Layer,
  type IPv4Layer,
  type IPv4Option,
  type IPv6Layer,
  type Layer,
  type TCPLayer,
  type TCPOption,
  type TCPSackBlock,
  type UDPLayer,
  type VLANLayer,
  type VXLANLayer,
} from './layers/types';
import { UDP_HEADER_LENGTH } from './layers/udp';
import { VLAN_HEADER_LENGTH, vlanInnerEtherTypeForUpperLayer } from './layers/vlan';
import { VXLAN_FLAG_I, VXLAN_HEADER_LENGTH, VXLAN_PORT } from './layers/vxlan';
import { err, ok, type Result } from './result';

export type DecodeStartLayer = 'ethernet' | 'ipv4' | 'ipv6';

export interface DecodedPacket {
  readonly layers: readonly Layer[];
  readonly payload: Uint8Array;
  /** Informational notes about unsupported/truncated or non-base header fields */
  readonly notes: readonly string[];
}

interface PseudoIPInfo {
  readonly version: 4 | 6;
  readonly srcIp: Uint8Array;
  readonly dstIp: Uint8Array;
}

function decodeARPAt(bytes: Uint8Array, offset: number): ARPLayer {
  const htype = readUint16BE(bytes, offset);
  const ptype = readUint16BE(bytes, offset + 2);
  const hlen = bytes[offset + 4];
  const plen = bytes[offset + 5];
  const operation = readUint16BE(bytes, offset + 6);

  return {
    type: 'arp',
    hardwareType: htype === ARP_HTYPE_ETHERNET ? autoValue() : manualValue(htype),
    protocolType: ptype === ARP_PTYPE_IPV4 ? autoValue() : manualValue(ptype),
    hardwareLength: hlen === ARP_HLEN_ETHERNET ? autoValue() : manualValue(hlen),
    protocolLength: plen === ARP_PLEN_IPV4 ? autoValue() : manualValue(plen),
    operation,
    senderMac: formatMac(bytes.subarray(offset + 8, offset + 14)),
    senderIp: formatIPv4(bytes.subarray(offset + 14, offset + 18)),
    targetMac: formatMac(bytes.subarray(offset + 18, offset + 24)),
    targetIp: formatIPv4(bytes.subarray(offset + 24, offset + 28)),
  };
}

function decodeICMPAt(bytes: Uint8Array, offset: number): { layer: ICMPLayer; payload: Uint8Array } {
  const icmpType = bytes[offset];
  const code = bytes[offset + 1];
  const checksum = readUint16BE(bytes, offset + 2);
  const identifier = readUint16BE(bytes, offset + 4);
  const sequenceNumber = readUint16BE(bytes, offset + 6);

  const segmentCopy = new Uint8Array(bytes.subarray(offset));
  segmentCopy[2] = 0;
  segmentCopy[3] = 0;
  const computed = internetChecksum(segmentCopy);

  return {
    layer: {
      type: 'icmp',
      icmpType,
      code,
      checksum: checksum === computed ? autoValue() : manualValue(checksum),
      identifier,
      sequenceNumber,
    },
    payload: bytes.slice(offset + ICMP_HEADER_LENGTH),
  };
}

function decodeICMPv6At(
  bytes: Uint8Array,
  offset: number,
  ip: PseudoIPInfo,
): { layer: ICMPv6Layer; payload: Uint8Array } {
  const icmpType = bytes[offset];
  const code = bytes[offset + 1];
  const checksum = readUint16BE(bytes, offset + 2);

  // Type 128 (Echo Request) and Type 129 (Echo Reply) always decode to the Echo variant
  // (even if originally constructed using the Raw 32-bit variant); the wire bytes are identical.
  const isEcho =
    icmpType === ICMPV6_TYPE_ECHO_REQUEST || icmpType === ICMPV6_TYPE_ECHO_REPLY;
  const rest = isEcho
    ? ({
        kind: 'echo',
        identifier: readUint16BE(bytes, offset + 4),
        sequence: readUint16BE(bytes, offset + 6),
      } as const)
    : ({
        kind: 'raw',
        value: readUint32BE(bytes, offset + 4),
      } as const);

  const segmentCopy = new Uint8Array(bytes.subarray(offset));
  segmentCopy[2] = 0;
  segmentCopy[3] = 0;
  const csumRes = computePseudoChecksum(ip, IP_PROTOCOL_ICMPV6, segmentCopy);
  const expectedChecksum = csumRes.ok ? csumRes.value : null;

  return {
    layer: {
      type: 'icmpv6',
      icmpType,
      code,
      checksum:
        expectedChecksum !== null && checksum === expectedChecksum
          ? autoValue()
          : manualValue(checksum),
      rest,
    },
    payload: bytes.slice(offset + ICMPV6_HEADER_LENGTH),
  };
}

function computePseudoChecksum(
  ip: PseudoIPInfo,
  protocol: number,
  segment: Uint8Array,
): Result<number> {
  return ip.version === 4
    ? ipv4PseudoHeaderChecksum({
        srcIp: ip.srcIp,
        dstIp: ip.dstIp,
        protocol,
        segment,
      })
    : ipv6PseudoHeaderChecksum({
        srcIp: ip.srcIp,
        dstIp: ip.dstIp,
        nextHeader: protocol,
        segment,
      });
}

function decodeUDPAt(
  bytes: Uint8Array,
  offset: number,
  ip: PseudoIPInfo,
): { layer: UDPLayer; payload: Uint8Array } {
  const srcPort = readUint16BE(bytes, offset);
  const dstPort = readUint16BE(bytes, offset + 2);
  const length = readUint16BE(bytes, offset + 4);
  const checksum = readUint16BE(bytes, offset + 6);

  const actualLength = bytes.length - offset;
  const segmentCopy = new Uint8Array(bytes.subarray(offset));
  segmentCopy[6] = 0;
  segmentCopy[7] = 0;

  const csumRes = computePseudoChecksum(ip, IP_PROTOCOL_UDP, segmentCopy);
  const expectedChecksum = csumRes.ok ? (csumRes.value === 0 ? 0xffff : csumRes.value) : null;

  return {
    layer: {
      type: 'udp',
      srcPort,
      dstPort,
      length: length === actualLength ? autoValue() : manualValue(length),
      checksum:
        expectedChecksum !== null && checksum === expectedChecksum
          ? autoValue()
          : manualValue(checksum),
    },
    payload: bytes.slice(offset + UDP_HEADER_LENGTH),
  };
}

function formatSpacedHexBytes(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return parts.join(' ');
}

function decodeTCPOptions(optBytes: Uint8Array, notes: string[]): TCPOption[] {
  const options: TCPOption[] = [];

  const pushMalformedRaw = (slice: Uint8Array, note: string) => {
    notes.push(note);
    if (slice.length === 1) {
      options.push({
        kind: 'raw',
        optionKind: slice[0],
        length: { mode: 'none' },
        dataHex: '',
      });
      return;
    }
    const lenByte = slice[1];
    if (lenByte < 2) {
      options.push({
        kind: 'raw',
        optionKind: slice[0],
        length: { mode: 'none' },
        dataHex: formatSpacedHexBytes(slice.subarray(1)),
      });
      return;
    }
    options.push({
      kind: 'raw',
      optionKind: slice[0],
      length: lenByte === slice.length ? autoValue() : manualValue(lenByte),
      dataHex: formatSpacedHexBytes(slice.subarray(2)),
    });
  };

  let i = 0;
  while (i < optBytes.length) {
    const kind = optBytes[i];

    if (kind === TCP_OPT_EOL) {
      // Stop without adding a synthetic EOL if remaining bytes are just 32-bit zero padding
      if (i > 0 && Math.ceil(i / 4) * 4 === optBytes.length && isAllZero(optBytes.subarray(i))) {
        break;
      }
      options.push({ kind: 'eol' });
      i += 1;
      if (i < optBytes.length && !isAllZero(optBytes.subarray(i))) {
        const trailing = optBytes.subarray(i);
        notes.push(
          `Preserved ${trailing.length} non-zero byte(s) after TCP End of Option List (Kind 0) as a raw option block.`,
        );
        options.push({
          kind: 'raw',
          optionKind: trailing[0],
          length: { mode: 'none' },
          dataHex: formatSpacedHexBytes(trailing.subarray(1)),
        });
        break;
      }
      continue;
    }

    if (kind === TCP_OPT_NOP) {
      options.push({ kind: 'nop' });
      i += 1;
      continue;
    }

    // TLV-formatted option (Kind + Length + Data)
    if (i + 1 >= optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Truncated TCP option (Kind ${kind}) missing Length byte; remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    const optLen = optBytes[i + 1];
    if (optLen < 2) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed TCP option (Kind ${kind}) has Length ${optLen} (< 2); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (i + optLen > optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed TCP option (Kind ${kind}) has Length ${optLen} exceeding remaining ${optBytes.length - i} option byte(s); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (kind === TCP_OPT_MSS) {
      if (optLen !== 4) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP MSS option (Kind 2) has Length ${optLen} (expected 4); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({ kind: 'mss', mss: readUint16BE(optBytes, i + 2) });
    } else if (kind === TCP_OPT_WINDOW_SCALE) {
      if (optLen !== 3) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP Window Scale option (Kind 3) has Length ${optLen} (expected 3); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({ kind: 'windowScale', shiftCount: optBytes[i + 2] });
    } else if (kind === TCP_OPT_SACK_PERMITTED) {
      if (optLen !== 2) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP SACK-Permitted option (Kind 4) has Length ${optLen} (expected 2); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({ kind: 'sackPermitted' });
    } else if (kind === TCP_OPT_SACK) {
      if (optLen < 10 || (optLen - 2) % 8 !== 0) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP SACK option (Kind 5) has Length ${optLen} (expected 2 + 8n, n >= 1); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      const blockCount = (optLen - 2) / 8;
      const blocks: TCPSackBlock[] = [];
      for (let b = 0; b < blockCount; b++) {
        const bOff = i + 2 + b * 8;
        blocks.push({
          left: readUint32BE(optBytes, bOff),
          right: readUint32BE(optBytes, bOff + 4),
        });
      }
      options.push({ kind: 'sack', blocks });
    } else if (kind === TCP_OPT_TIMESTAMPS) {
      if (optLen !== 10) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP Timestamps option (Kind 8) has Length ${optLen} (expected 10); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({
        kind: 'timestamps',
        tsVal: readUint32BE(optBytes, i + 2),
        tsEcr: readUint32BE(optBytes, i + 6),
      });
    } else {
      options.push({
        kind: 'raw',
        optionKind: kind,
        length: autoValue(),
        dataHex: formatSpacedHexBytes(optBytes.subarray(i + 2, i + optLen)),
      });
    }

    i += optLen;
  }

  return options;
}

function decodeTCPAt(
  bytes: Uint8Array,
  offset: number,
  ip: PseudoIPInfo,
  notes: string[],
): { layer: TCPLayer; payload: Uint8Array } {
  const srcPort = readUint16BE(bytes, offset);
  const dstPort = readUint16BE(bytes, offset + 2);
  const seqNumber = readUint32BE(bytes, offset + 4);
  const ackNumber = readUint32BE(bytes, offset + 8);
  const dataOffsetAndReserved = bytes[offset + 12];
  const dataOffset = dataOffsetAndReserved >>> 4;
  const reserved = dataOffsetAndReserved & 0x0f;
  const flagsByte = bytes[offset + 13];
  const windowSize = readUint16BE(bytes, offset + 14);
  const checksum = readUint16BE(bytes, offset + 16);
  const urgentPointer = readUint16BE(bytes, offset + 18);

  const segmentLength = bytes.length - offset;
  const declaredHeaderLength = dataOffset * 4;
  let options: TCPOption[] = [];
  let payloadOffset = offset + TCP_HEADER_LENGTH;
  let dataOffsetField =
    dataOffset === TCP_DEFAULT_DATA_OFFSET ? autoValue<number>() : manualValue(dataOffset);

  if (dataOffset > TCP_DEFAULT_DATA_OFFSET) {
    if (segmentLength >= declaredHeaderLength) {
      const optBytes = bytes.subarray(offset + TCP_HEADER_LENGTH, offset + declaredHeaderLength);
      options = decodeTCPOptions(optBytes, notes);
      payloadOffset = offset + declaredHeaderLength;
      dataOffsetField = autoValue();
    } else {
      notes.push(
        `TCP Data Offset is ${dataOffset} (${declaredHeaderLength} bytes), exceeding the ${segmentLength}-byte segment; bytes beyond the 20-byte base header are placed in Payload.`,
      );
    }
  }
  if (reserved !== 0) {
    notes.push(
      `TCP Reserved bits were non-zero (0x${reserved.toString(16)}); the encoder resets Reserved to 0 per RFC 9293, so re-encoded bytes and checksum will differ from the original input.`,
    );
  }

  const segmentCopy = new Uint8Array(bytes.subarray(offset));
  segmentCopy[16] = 0;
  segmentCopy[17] = 0;
  const csumRes = computePseudoChecksum(ip, IP_PROTOCOL_TCP, segmentCopy);
  const expectedChecksum = csumRes.ok ? csumRes.value : null;

  return {
    layer: {
      type: 'tcp',
      srcPort,
      dstPort,
      seqNumber,
      ackNumber,
      dataOffset: dataOffsetField,
      flags: {
        cwr: (flagsByte & 0x80) !== 0,
        ece: (flagsByte & 0x40) !== 0,
        urg: (flagsByte & 0x20) !== 0,
        ack: (flagsByte & 0x10) !== 0,
        psh: (flagsByte & 0x08) !== 0,
        rst: (flagsByte & 0x04) !== 0,
        syn: (flagsByte & 0x02) !== 0,
        fin: (flagsByte & 0x01) !== 0,
      },
      windowSize,
      checksum:
        expectedChecksum !== null && checksum === expectedChecksum
          ? autoValue()
          : manualValue(checksum),
      urgentPointer,
      options,
    },
    payload: bytes.slice(payloadOffset),
  };
}

const BGP_TYPE_NAMES: Readonly<Record<BGPMessageType, string>> = {
  1: 'OPEN',
  2: 'UPDATE',
  3: 'NOTIFICATION',
  4: 'KEEPALIVE',
};

function isBGPMessageType(value: number): value is BGPMessageType {
  return (
    value === BGP_TYPE_OPEN ||
    value === BGP_TYPE_UPDATE ||
    value === BGP_TYPE_NOTIFICATION ||
    value === BGP_TYPE_KEEPALIVE
  );
}

function decodeBGPAt(
  tcpPayload: Uint8Array,
  notes: string[],
): { layer: BGPLayer; payload: Uint8Array } | null {
  // RFC 4271 §4.1: BGP messages begin with a 16-octet all-ones Marker (0xff * 16).
  if (tcpPayload.length < 16 || !isAllFF(tcpPayload.subarray(0, 16))) {
    return null;
  }

  if (tcpPayload.length < BGP_COMMON_HEADER_LENGTH) {
    notes.push(
      `BGP-4 message on TCP port 179 is truncated (${tcpPayload.length} bytes, need at least ${BGP_COMMON_HEADER_LENGTH}); remaining bytes kept as Payload.`,
    );
    return null;
  }

  const bgpLength = readUint16BE(tcpPayload, 16);
  const rawType = tcpPayload[18];

  if (!isBGPMessageType(rawType)) {
    notes.push(
      `BGP message Type ${rawType} is not decoded into a layer (supported: 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE); remaining bytes kept as Payload.`,
    );
    return null;
  }

  const headerLen = getBGPHeaderLength(rawType);
  if (tcpPayload.length < headerLen) {
    notes.push(
      `BGP-4 ${BGP_TYPE_NAMES[rawType]} message on TCP port 179 is truncated (${tcpPayload.length} bytes, need at least ${headerLen}); remaining bytes kept as Payload.`,
    );
    return null;
  }

  if (bgpLength < headerLen) {
    notes.push(
      `BGP Length (${bgpLength}) is smaller than the ${headerLen}-byte ${BGP_TYPE_NAMES[rawType]} header; kept as manual Length.`,
    );
  } else if (bgpLength < tcpPayload.length) {
    notes.push(
      `BGP Length (${bgpLength}) is smaller than TCP payload (${tcpPayload.length} bytes); additional bytes (e.g., pipelined BGP messages) are preserved in Payload.`,
    );
  } else if (bgpLength > tcpPayload.length) {
    notes.push(
      `BGP Length (${bgpLength}) exceeds available TCP payload (${tcpPayload.length} bytes); kept as manual Length.`,
    );
  }

  const baseLayer: BGPLayer = {
    type: 'bgp',
    bgpType: rawType,
    marker: autoValue<string>(),
    length: bgpLength === tcpPayload.length ? autoValue() : manualValue(bgpLength),
    version: autoValue(),
    myAs: 65001,
    holdTime: 180,
    bgpIdentifier: '192.0.2.1',
    optParamLength: autoValue(),
    withdrawnRoutesLength: autoValue(),
    totalPathAttrLength: autoValue(),
    errorCode: 6,
    errorSubcode: 0,
  };

  if (rawType === BGP_TYPE_OPEN) {
    const versionByte = tcpPayload[19];
    const myAs = readUint16BE(tcpPayload, 20);
    const holdTime = readUint16BE(tcpPayload, 22);
    const bgpIdentifier = formatIPv4(tcpPayload.subarray(24, 28));
    const optParamLen = tcpPayload[28];
    const remainingPayload = tcpPayload.slice(headerLen);

    return {
      layer: {
        ...baseLayer,
        version: versionByte === BGP_VERSION_4 ? autoValue() : manualValue(versionByte),
        myAs,
        holdTime,
        bgpIdentifier,
        optParamLength:
          optParamLen === remainingPayload.length ? autoValue() : manualValue(optParamLen),
      },
      payload: remainingPayload,
    };
  }

  if (rawType === BGP_TYPE_UPDATE) {
    const withdrawnLen = readUint16BE(tcpPayload, 19);
    const attrLen = readUint16BE(tcpPayload, 21);
    const remainingPayload = tcpPayload.slice(headerLen);

    if (withdrawnLen > 0) {
      notes.push(
        `BGP UPDATE has non-zero Withdrawn Routes Length (${withdrawnLen}); RFC 4271 §4.3 places Withdrawn Routes before Total Path Attribute Length, so bytes 21..22 were preserved in Total Path Attribute Length for lossless round-trip.`,
      );
    }

    return {
      layer: {
        ...baseLayer,
        withdrawnRoutesLength: withdrawnLen === 0 ? autoValue() : manualValue(withdrawnLen),
        totalPathAttrLength: attrLen === 0 ? autoValue() : manualValue(attrLen),
      },
      payload: remainingPayload,
    };
  }

  if (rawType === BGP_TYPE_NOTIFICATION) {
    const errorCode = tcpPayload[19];
    const errorSubcode = tcpPayload[20];
    return {
      layer: {
        ...baseLayer,
        errorCode,
        errorSubcode,
      },
      payload: tcpPayload.slice(headerLen),
    };
  }

  // Type 4: KEEPALIVE
  return {
    layer: baseLayer,
    payload: tcpPayload.slice(headerLen),
  };
}

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

/** Maximum total IP layers decoded (outer + nested IPv4/IPv6 tunnels) to guard against pathological inputs */
const MAX_IP_LAYERS = 16;

const IPV6_EXTENSION_HEADER_NAMES: Readonly<Record<number, string>> = {
  0: 'Hop-by-Hop Options',
  43: 'Routing',
  44: 'Fragment',
  50: 'ESP',
  51: 'AH',
  60: 'Destination Options',
};

function decodeTCPAndBGPAt(
  scopedBytes: Uint8Array,
  upperOffset: number,
  ip: PseudoIPInfo,
  decodedUpperLayers: Layer[],
  notes: string[],
): Uint8Array {
  const res = decodeTCPAt(scopedBytes, upperOffset, ip, notes);
  decodedUpperLayers.push(res.layer);
  const isBgpPort = res.layer.srcPort === BGP_PORT || res.layer.dstPort === BGP_PORT;
  if (isBgpPort && res.payload.length > 0) {
    if (res.layer.dataOffset.mode === 'auto') {
      const bgpRes = decodeBGPAt(res.payload, notes);
      if (bgpRes !== null) {
        decodedUpperLayers.push(bgpRes.layer);
        return bgpRes.payload;
      }
      return res.payload;
    }
    if (res.layer.dataOffset.value < TCP_DEFAULT_DATA_OFFSET) {
      notes.push(
        `TCP segment on port 179 has invalid Data Offset (${res.layer.dataOffset.value}); BGP-4 decoding skipped.`,
      );
    }
  }
  return res.payload;
}

function decodeUDPAndVXLANAt(
  scopedBytes: Uint8Array,
  upperOffset: number,
  ipInfo: PseudoIPInfo,
  decodedUpperLayers: Layer[],
  notes: string[],
  depth: number,
): Uint8Array {
  const res = decodeUDPAt(scopedBytes, upperOffset, ipInfo);
  decodedUpperLayers.push(res.layer);

  if (res.layer.dstPort !== VXLAN_PORT) {
    return res.payload;
  }

  if (res.payload.length < VXLAN_HEADER_LENGTH) {
    if (res.payload.length > 0) {
      notes.push(
        `UDP payload on port ${VXLAN_PORT} is too short for a VXLAN header (${res.payload.length} bytes, need at least ${VXLAN_HEADER_LENGTH}); remaining bytes kept as Payload.`,
      );
    }
    return res.payload;
  }

  const vxlanOffset = upperOffset + UDP_HEADER_LENGTH;
  const flags = scopedBytes[vxlanOffset];
  if ((flags & VXLAN_FLAG_I) === 0) {
    notes.push(
      `UDP payload on port ${VXLAN_PORT} does not have the VXLAN I-flag (0x08) set (Flags 0x${flags.toString(16).padStart(2, '0')}); per RFC 7348 §5 remaining bytes are kept as Payload.`,
    );
    return res.payload;
  }

  const reserved1 =
    (scopedBytes[vxlanOffset + 1] << 16) |
    (scopedBytes[vxlanOffset + 2] << 8) |
    scopedBytes[vxlanOffset + 3];
  const vni =
    (scopedBytes[vxlanOffset + 4] << 16) |
    (scopedBytes[vxlanOffset + 5] << 8) |
    scopedBytes[vxlanOffset + 6];
  const reserved2 = scopedBytes[vxlanOffset + 7];

  const vxlanLayer: VXLANLayer = {
    type: 'vxlan',
    flags: flags === VXLAN_FLAG_I ? autoValue() : manualValue(flags),
    vni,
    reserved1,
    reserved2,
  };
  decodedUpperLayers.push(vxlanLayer);

  const innerOffset = vxlanOffset + VXLAN_HEADER_LENGTH;
  const innerRemaining = scopedBytes.length - innerOffset;

  if (depth + 1 >= MAX_IP_LAYERS) {
    notes.push(
      `VXLAN tunnel depth limit (${MAX_IP_LAYERS}) exceeded; remaining bytes kept as Payload.`,
    );
    return scopedBytes.slice(innerOffset);
  }

  if (innerRemaining < ETHERNET_HEADER_LENGTH) {
    if (innerRemaining > 0) {
      notes.push(
        `Inner Ethernet II frame after VXLAN is truncated (${innerRemaining} bytes); remaining bytes kept as Payload.`,
      );
    }
    return scopedBytes.slice(innerOffset);
  }

  const innerLayers: Layer[] = [];
  const innerPayload = decodeEthernetFrameAt(
    scopedBytes,
    innerOffset,
    innerLayers,
    notes,
    depth + 1,
  );
  decodedUpperLayers.push(...innerLayers);
  return innerPayload;
}

function decodeIPv4Options(optBytes: Uint8Array, notes: string[]): IPv4Option[] {
  const options: IPv4Option[] = [];

  const pushMalformedRaw = (slice: Uint8Array, note: string) => {
    notes.push(note);
    if (slice.length === 1) {
      options.push({
        kind: 'raw',
        optionType: slice[0],
        length: { mode: 'none' },
        dataHex: '',
      });
      return;
    }
    const lenByte = slice[1];
    if (lenByte < 2) {
      options.push({
        kind: 'raw',
        optionType: slice[0],
        length: { mode: 'none' },
        dataHex: formatSpacedHexBytes(slice.subarray(1)),
      });
      return;
    }
    options.push({
      kind: 'raw',
      optionType: slice[0],
      length: lenByte === slice.length ? autoValue() : manualValue(lenByte),
      dataHex: formatSpacedHexBytes(slice.subarray(2)),
    });
  };

  let i = 0;
  while (i < optBytes.length) {
    const typeByte = optBytes[i];

    if (typeByte === IPV4_OPT_EOL) {
      if (i > 0 && Math.ceil(i / 4) * 4 === optBytes.length && isAllZero(optBytes.subarray(i))) {
        break;
      }
      options.push({ kind: 'eol' });
      i += 1;
      if (i < optBytes.length && !isAllZero(optBytes.subarray(i))) {
        const trailing = optBytes.subarray(i);
        notes.push(
          `Preserved ${trailing.length} non-zero byte(s) after IPv4 End of Option List (Type 0) as a raw option block.`,
        );
        options.push({
          kind: 'raw',
          optionType: trailing[0],
          length: { mode: 'none' },
          dataHex: formatSpacedHexBytes(trailing.subarray(1)),
        });
        break;
      }
      continue;
    }

    if (typeByte === IPV4_OPT_NOP) {
      options.push({ kind: 'nop' });
      i += 1;
      continue;
    }

    if (i + 1 >= optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Truncated IPv4 option (Type ${typeByte}) missing Length byte; remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    const optLen = optBytes[i + 1];
    if (optLen < 2) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed IPv4 option (Type ${typeByte}) has Length ${optLen} (< 2); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (i + optLen > optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed IPv4 option (Type ${typeByte}) has Length ${optLen} exceeding remaining ${optBytes.length - i} option byte(s); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (
      typeByte === IPV4_OPT_RR ||
      typeByte === IPV4_OPT_LSRR ||
      typeByte === IPV4_OPT_SSRR
    ) {
      const kind =
        typeByte === IPV4_OPT_RR ? 'rr' : typeByte === IPV4_OPT_LSRR ? 'lsrr' : 'ssrr';
      if (optLen < 3 || (optLen - 3) % 4 !== 0) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed IPv4 ${kind.toUpperCase()} option (Type ${typeByte}) has Length ${optLen} (expected 3 + 4n); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      const ptr = optBytes[i + 2];
      const addrCount = (optLen - 3) / 4;
      const addresses: string[] = [];
      for (let a = 0; a < addrCount; a++) {
        const aOff = i + 3 + a * 4;
        addresses.push(formatIPv4(optBytes.subarray(aOff, aOff + 4)));
      }
      options.push({
        kind,
        pointer: ptr === 4 ? autoValue() : manualValue(ptr),
        addresses,
      });
    } else if (typeByte === IPV4_OPT_TIMESTAMP) {
      if (optLen < 4) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed IPv4 Timestamp option (Type 68) has Length ${optLen} (expected >= 4); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      const pointer = optBytes[i + 2];
      const ovflFlag = optBytes[i + 3];
      options.push({
        kind: 'timestamp',
        pointer,
        overflow: (ovflFlag >>> 4) & 0x0f,
        flag: ovflFlag & 0x0f,
        dataHex: formatSpacedHexBytes(optBytes.subarray(i + 4, i + optLen)),
      });
    } else if (typeByte === IPV4_OPT_ROUTER_ALERT) {
      if (optLen !== 4) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed IPv4 Router Alert option (Type 148) has Length ${optLen} (expected 4); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({
        kind: 'routerAlert',
        value: readUint16BE(optBytes, i + 2),
      });
    } else {
      options.push({
        kind: 'raw',
        optionType: typeByte,
        length: autoValue(),
        dataHex: formatSpacedHexBytes(optBytes.subarray(i + 2, i + optLen)),
      });
    }

    i += optLen;
  }

  return options;
}

function tryDecodeInnerIPv4(
  scopedBytes: Uint8Array,
  upperOffset: number,
  upperRemaining: number,
  decodedUpperLayers: Layer[],
  notes: string[],
  depth: number,
  enclosingLabel = `Protocol ${IP_PROTOCOL_IPIP}`,
): Uint8Array | null {
  if (depth + 1 >= MAX_IP_LAYERS) {
    notes.push(
      `IP tunnel layer limit (${MAX_IP_LAYERS} IP layers) exceeded; remaining bytes kept as Payload.`,
    );
    return null;
  }
  const innerVersion = scopedBytes[upperOffset] >>> 4;
  const innerIhl = scopedBytes[upperOffset] & 0x0f;
  const innerTotalLength = readUint16BE(scopedBytes, upperOffset + 2);
  if (innerVersion !== IPV4_VERSION || innerIhl < IPV4_IHL) {
    notes.push(
      `Inner IPv4 header (${enclosingLabel}) has Version=${innerVersion}, IHL=${innerIhl} (expected Version=4, IHL >= 5); remaining bytes kept as Payload.`,
    );
    return null;
  }
  const innerHeaderLength = innerIhl * 4;
  if (upperRemaining < innerHeaderLength) {
    notes.push(
      `Inner IPv4 header (${enclosingLabel}) is truncated (${upperRemaining} bytes available, IHL=${innerIhl} requires ${innerHeaderLength} bytes); remaining bytes kept as Payload.`,
    );
    return null;
  }
  if (innerTotalLength >= innerHeaderLength && innerTotalLength < upperRemaining) {
    notes.push(
      `Inner IPv4 Total Length (${innerTotalLength}) is smaller than the enclosing IP payload (${upperRemaining} bytes); inner packet and trailing bytes kept in Payload to preserve exact round-trip bytes.`,
    );
    return null;
  }
  return decodeIPv4Chain(scopedBytes, upperOffset, decodedUpperLayers, notes, depth + 1);
}

function tryDecodeInnerIPv6(
  scopedBytes: Uint8Array,
  upperOffset: number,
  upperRemaining: number,
  decodedUpperLayers: Layer[],
  notes: string[],
  depth: number,
  enclosingLabel = `Protocol ${IP_PROTOCOL_IPV6}`,
): Uint8Array | null {
  if (depth + 1 >= MAX_IP_LAYERS) {
    notes.push(
      `IP tunnel layer limit (${MAX_IP_LAYERS} IP layers) exceeded; remaining bytes kept as Payload.`,
    );
    return null;
  }
  const innerVersion = scopedBytes[upperOffset] >>> 4;
  const innerPayloadLength = readUint16BE(scopedBytes, upperOffset + 4);
  if (innerVersion !== IPV6_VERSION) {
    notes.push(
      `Inner IPv6 header (${enclosingLabel}) has Version=${innerVersion} (expected Version=6); remaining bytes kept as Payload.`,
    );
    return null;
  }
  const innerAvailablePayload = upperRemaining - IPV6_HEADER_LENGTH;
  if (innerPayloadLength < innerAvailablePayload) {
    notes.push(
      `Inner IPv6 Payload Length (${innerPayloadLength}) is smaller than the enclosing IP payload (${innerAvailablePayload} bytes after 40-byte header); inner packet and trailing bytes kept in Payload to preserve exact round-trip bytes.`,
    );
    return null;
  }
  return decodeIPv6Chain(scopedBytes, upperOffset, decodedUpperLayers, notes, depth + 1);
}

function decodeIPv4Chain(
  bytes: Uint8Array,
  offset: number,
  layers: Layer[],
  notes: string[],
  depth = 0,
): Uint8Array {
  const ihl = bytes[offset] & 0x0f;
  const headerLength = ihl * 4;
  const tos = bytes[offset + 1];
  const totalLength = readUint16BE(bytes, offset + 2);
  const identification = readUint16BE(bytes, offset + 4);
  const flagsAndFrag = readUint16BE(bytes, offset + 6);
  const fragmentOffset = flagsAndFrag & 0x1fff;
  const ttl = bytes[offset + 8];
  const protocol = bytes[offset + 9];
  const headerChecksum = readUint16BE(bytes, offset + 10);
  const srcIpBytes = bytes.subarray(offset + 12, offset + 16);
  const dstIpBytes = bytes.subarray(offset + 16, offset + 20);
  const ipInfo: PseudoIPInfo = { version: 4, srcIp: srcIpBytes, dstIp: dstIpBytes };

  const actualTotalLength = bytes.length - offset;
  let scopedBytes = bytes;
  let effectiveTotalLength = actualTotalLength;

  if (depth === 0 && totalLength >= headerLength && totalLength < actualTotalLength) {
    const trailing = bytes.subarray(offset + totalLength);
    // Per RFC 791 / RFC 768 / RFC 9293 §3.1, upper-layer segments and checksums are bounded
    // strictly by the outermost IPv4 Total Length regardless of whether Ethernet padding bytes are zero or non-zero.
    scopedBytes = bytes.subarray(0, offset + totalLength);
    effectiveTotalLength = totalLength;
    if (isAllZero(trailing)) {
      notes.push(
        `Stripped ${trailing.length} trailing zero byte(s) of Ethernet padding beyond IPv4 Total Length (${totalLength}).`,
      );
    } else {
      notes.push(
        `Stripped ${trailing.length} trailing non-zero byte(s) of Ethernet padding/trailer beyond IPv4 Total Length (${totalLength}) per RFC 791/768/9293; re-encoded bytes will omit these trailing bytes.`,
      );
    }
  }

  const headerCopy = new Uint8Array(scopedBytes.subarray(offset, offset + headerLength));
  headerCopy[10] = 0;
  headerCopy[11] = 0;
  const computedHeaderChecksum = internetChecksum(headerCopy);

  const options =
    ihl > IPV4_IHL
      ? decodeIPv4Options(
          scopedBytes.subarray(offset + IPV4_HEADER_LENGTH, offset + headerLength),
          notes,
        )
      : [];

  const upperOffset = offset + headerLength;
  const upperRemaining = scopedBytes.length - upperOffset;

  const decodedUpperLayers: Layer[] = [];
  let payload: Uint8Array = scopedBytes.slice(upperOffset);

  if (fragmentOffset !== 0) {
    // RFC 791: non-initial fragments carry continuation payload rather than an L4 header
    notes.push(
      `Non-initial IPv4 fragment (Fragment Offset = ${fragmentOffset}); upper-layer header is not decoded per RFC 791 and remaining bytes are kept as Payload.`,
    );
  } else if (protocol === IP_PROTOCOL_IPIP && upperRemaining >= IPV4_HEADER_LENGTH) {
    const innerPayload = tryDecodeInnerIPv4(
      scopedBytes,
      upperOffset,
      upperRemaining,
      decodedUpperLayers,
      notes,
      depth,
    );
    if (innerPayload !== null) {
      payload = innerPayload;
    }
  } else if (protocol === IP_PROTOCOL_IPV6 && upperRemaining >= IPV6_HEADER_LENGTH) {
    const innerPayload = tryDecodeInnerIPv6(
      scopedBytes,
      upperOffset,
      upperRemaining,
      decodedUpperLayers,
      notes,
      depth,
    );
    if (innerPayload !== null) {
      payload = innerPayload;
    }
  } else if (protocol === IP_PROTOCOL_GRE && upperRemaining >= GRE_BASE_HEADER_LENGTH) {
    const innerPayload = decodeGREAt(
      scopedBytes,
      upperOffset,
      upperRemaining,
      decodedUpperLayers,
      notes,
      depth,
    );
    if (innerPayload !== null) {
      payload = innerPayload;
    }
  } else if (protocol === IP_PROTOCOL_ICMP && upperRemaining >= ICMP_HEADER_LENGTH) {
    const res = decodeICMPAt(scopedBytes, upperOffset);
    decodedUpperLayers.push(res.layer);
    payload = res.payload;
  } else if (protocol === IP_PROTOCOL_UDP && upperRemaining >= UDP_HEADER_LENGTH) {
    payload = decodeUDPAndVXLANAt(
      scopedBytes,
      upperOffset,
      ipInfo,
      decodedUpperLayers,
      notes,
      depth,
    );
  } else if (protocol === IP_PROTOCOL_TCP && upperRemaining >= TCP_HEADER_LENGTH) {
    payload = decodeTCPAndBGPAt(scopedBytes, upperOffset, ipInfo, decodedUpperLayers, notes);
  } else if (
    protocol === IP_PROTOCOL_IPIP ||
    protocol === IP_PROTOCOL_IPV6 ||
    protocol === IP_PROTOCOL_GRE ||
    protocol === IP_PROTOCOL_ICMP ||
    protocol === IP_PROTOCOL_UDP ||
    protocol === IP_PROTOCOL_TCP
  ) {
    notes.push(
      `Upper-layer header for IPv4 Protocol ${protocol} is truncated (${upperRemaining} bytes); remaining bytes kept as Payload.`,
    );
  } else {
    notes.push(
      `IPv4 Protocol ${protocol} is not decoded into a layer; remaining bytes kept as Payload.`,
    );
  }

  const ipv4Layer: IPv4Layer = {
    type: 'ipv4',
    ihl: autoValue(),
    tos,
    totalLength: totalLength === effectiveTotalLength ? autoValue() : manualValue(totalLength),
    identification,
    flags: {
      reserved: (flagsAndFrag & 0x8000) !== 0,
      df: (flagsAndFrag & 0x4000) !== 0,
      mf: (flagsAndFrag & 0x2000) !== 0,
    },
    fragmentOffset,
    ttl,
    protocol: decodedUpperLayers.length > 0 ? autoValue() : manualValue(protocol),
    headerChecksum:
      headerChecksum === computedHeaderChecksum ? autoValue() : manualValue(headerChecksum),
    srcIp: formatIPv4(srcIpBytes),
    dstIp: formatIPv4(dstIpBytes),
    options,
  };

  layers.push(ipv4Layer, ...decodedUpperLayers);
  return payload;
}

function decodeIPv6Chain(
  bytes: Uint8Array,
  offset: number,
  layers: Layer[],
  notes: string[],
  depth = 0,
): Uint8Array {
  const firstWord = readUint32BE(bytes, offset);
  const trafficClass = (firstWord >>> 20) & 0xff;
  const flowLabel = firstWord & 0xfffff;
  const payloadLength = readUint16BE(bytes, offset + 4);
  const nextHeader = bytes[offset + 6];
  const hopLimit = bytes[offset + 7];
  const srcIpBytes = bytes.subarray(offset + 8, offset + 24);
  const dstIpBytes = bytes.subarray(offset + 24, offset + 40);
  const ipInfo: PseudoIPInfo = { version: 6, srcIp: srcIpBytes, dstIp: dstIpBytes };

  const upperOffset = offset + IPV6_HEADER_LENGTH;
  const actualPayloadLength = bytes.length - upperOffset;
  let scopedBytes = bytes;
  let effectivePayloadLength = actualPayloadLength;
  const isJumbogramShape =
    payloadLength === 0 && nextHeader === 0 && actualPayloadLength > 0;

  if (depth === 0 && isJumbogramShape) {
    notes.push(
      'IPv6 Payload Length is 0 with Next Header 0 (Hop-by-Hop Options); Jumbogram (RFC 2675 §2) is not supported, so remaining bytes are kept as Payload.',
    );
  } else if (depth === 0 && payloadLength < actualPayloadLength) {
    const trailing = bytes.subarray(upperOffset + payloadLength);
    // Per RFC 8200 §3 / §8.1, upper-layer segments and checksums are bounded by IPv6 Payload Length.
    scopedBytes = bytes.subarray(0, upperOffset + payloadLength);
    effectivePayloadLength = payloadLength;
    const isInsideEthernet = offset > 0;
    if (isInsideEthernet) {
      if (isAllZero(trailing)) {
        notes.push(
          `Stripped ${trailing.length} trailing zero byte(s) of Ethernet padding beyond IPv6 Payload Length (${payloadLength}).`,
        );
      } else {
        notes.push(
          `Stripped ${trailing.length} trailing non-zero byte(s) of Ethernet padding/trailer beyond IPv6 Payload Length (${payloadLength}) per RFC 8200 §3; re-encoded bytes will omit these trailing bytes.`,
        );
      }
    } else {
      notes.push(
        `Stripped ${trailing.length} trailing byte(s) beyond IPv6 Payload Length (${payloadLength}) per RFC 8200 §3; re-encoded bytes will omit these trailing bytes.`,
      );
    }
  }

  const upperRemaining = scopedBytes.length - upperOffset;
  const decodedUpperLayers: Layer[] = [];
  let payload: Uint8Array = scopedBytes.slice(upperOffset);

  if (depth === 0 && isJumbogramShape) {
    // Already noted as an unsupported RFC 2675 §2 Jumbogram; keep remaining bytes in Payload.
  } else if (Object.prototype.hasOwnProperty.call(IPV6_EXTENSION_HEADER_NAMES, nextHeader)) {
    notes.push(
      `IPv6 extension header Next Header ${nextHeader} (${IPV6_EXTENSION_HEADER_NAMES[nextHeader]}) is not decoded into a layer; remaining bytes kept as Payload.`,
    );
  } else if (nextHeader === IP_PROTOCOL_IPIP && upperRemaining >= IPV4_HEADER_LENGTH) {
    const innerPayload = tryDecodeInnerIPv4(
      scopedBytes,
      upperOffset,
      upperRemaining,
      decodedUpperLayers,
      notes,
      depth,
    );
    if (innerPayload !== null) {
      payload = innerPayload;
    }
  } else if (nextHeader === IP_PROTOCOL_IPV6 && upperRemaining >= IPV6_HEADER_LENGTH) {
    const innerPayload = tryDecodeInnerIPv6(
      scopedBytes,
      upperOffset,
      upperRemaining,
      decodedUpperLayers,
      notes,
      depth,
    );
    if (innerPayload !== null) {
      payload = innerPayload;
    }
  } else if (nextHeader === IP_PROTOCOL_GRE && upperRemaining >= GRE_BASE_HEADER_LENGTH) {
    const innerPayload = decodeGREAt(
      scopedBytes,
      upperOffset,
      upperRemaining,
      decodedUpperLayers,
      notes,
      depth,
    );
    if (innerPayload !== null) {
      payload = innerPayload;
    }
  } else if (nextHeader === IP_PROTOCOL_ICMPV6 && upperRemaining >= ICMPV6_HEADER_LENGTH) {
    const res = decodeICMPv6At(scopedBytes, upperOffset, ipInfo);
    decodedUpperLayers.push(res.layer);
    payload = res.payload;
  } else if (nextHeader === IP_PROTOCOL_UDP && upperRemaining >= UDP_HEADER_LENGTH) {
    payload = decodeUDPAndVXLANAt(
      scopedBytes,
      upperOffset,
      ipInfo,
      decodedUpperLayers,
      notes,
      depth,
    );
  } else if (nextHeader === IP_PROTOCOL_TCP && upperRemaining >= TCP_HEADER_LENGTH) {
    payload = decodeTCPAndBGPAt(scopedBytes, upperOffset, ipInfo, decodedUpperLayers, notes);
  } else if (
    nextHeader === IP_PROTOCOL_IPIP ||
    nextHeader === IP_PROTOCOL_IPV6 ||
    nextHeader === IP_PROTOCOL_GRE ||
    nextHeader === IP_PROTOCOL_ICMPV6 ||
    nextHeader === IP_PROTOCOL_UDP ||
    nextHeader === IP_PROTOCOL_TCP
  ) {
    notes.push(
      `Upper-layer header for IPv6 Next Header ${nextHeader} is truncated (${upperRemaining} bytes); remaining bytes kept as Payload.`,
    );
  } else {
    notes.push(
      `IPv6 Next Header ${nextHeader} is not decoded into a layer; remaining bytes kept as Payload.`,
    );
  }

  const ipv6Layer: IPv6Layer = {
    type: 'ipv6',
    trafficClass,
    flowLabel,
    payloadLength:
      payloadLength === effectivePayloadLength ? autoValue() : manualValue(payloadLength),
    nextHeader: decodedUpperLayers.length > 0 ? autoValue() : manualValue(nextHeader),
    hopLimit,
    srcIp: formatIPv6(srcIpBytes),
    dstIp: formatIPv6(dstIpBytes),
  };

  layers.push(ipv6Layer, ...decodedUpperLayers);
  return payload;
}

function decodeGREAt(
  scopedBytes: Uint8Array,
  upperOffset: number,
  upperRemaining: number,
  decodedUpperLayers: Layer[],
  notes: string[],
  depth: number,
): Uint8Array | null {
  const flagsAndVersion = readUint16BE(scopedBytes, upperOffset);
  const protocolType = readUint16BE(scopedBytes, upperOffset + 2);

  const checksumPresent = (flagsAndVersion & 0x8000) !== 0;
  const reservedBit1 = (flagsAndVersion & 0x4000) !== 0;
  const keyPresent = (flagsAndVersion & 0x2000) !== 0;
  const sequencePresent = (flagsAndVersion & 0x1000) !== 0;
  const reserved0 = (flagsAndVersion >>> 3) & 0x1ff;
  const version = flagsAndVersion & 0x7;

  if (version !== 0) {
    notes.push(
      `GRE header has Version=${version} (only Version=0 per RFC 2784 §2.3.1 is supported; e.g., Version=1 is PPTP enhanced GRE); remaining bytes kept as Payload.`,
    );
    return null;
  }

  if (reservedBit1 || reserved0 !== 0) {
    notes.push(
      `GRE header has non-zero Reserved0 bits (flags word 0x${flagsAndVersion.toString(16).padStart(4, '0')}); remaining bytes kept as Payload to preserve exact bytes.`,
    );
    return null;
  }

  const headerLength = getGREHeaderLength({
    checksumPresent,
    keyPresent,
    sequencePresent,
  });

  if (upperRemaining < headerLength) {
    notes.push(
      `GRE header is truncated (${upperRemaining} bytes available, ${headerLength} bytes required for C=${checksumPresent ? 1 : 0}/K=${keyPresent ? 1 : 0}/S=${sequencePresent ? 1 : 0}); remaining bytes kept as Payload.`,
    );
    return null;
  }

  let cursor = upperOffset + GRE_BASE_HEADER_LENGTH;
  let checksumField = 0;
  let checksumOffsetInHeader = -1;
  if (checksumPresent) {
    checksumOffsetInHeader = cursor - upperOffset;
    checksumField = readUint16BE(scopedBytes, cursor);
    const reserved1 = readUint16BE(scopedBytes, cursor + 2);
    if (reserved1 !== 0) {
      notes.push(
        `GRE header has non-zero Reserved1 field (0x${reserved1.toString(16).padStart(4, '0')}); remaining bytes kept as Payload to preserve exact bytes.`,
      );
      return null;
    }
    cursor += 4;
  }

  let key = 0;
  if (keyPresent) {
    key = readUint32BE(scopedBytes, cursor);
    cursor += 4;
  }

  let sequenceNumber = 0;
  if (sequencePresent) {
    sequenceNumber = readUint32BE(scopedBytes, cursor);
    cursor += 4;
  }

  let checksumAutoOrManual = autoValue<number>();
  if (checksumPresent) {
    const greCopy = new Uint8Array(scopedBytes.subarray(upperOffset));
    greCopy[checksumOffsetInHeader] = 0;
    greCopy[checksumOffsetInHeader + 1] = 0;
    const computedChecksum = internetChecksum(greCopy);
    checksumAutoOrManual =
      checksumField === computedChecksum ? autoValue() : manualValue(checksumField);
  }

  const innerOffset = upperOffset + headerLength;
  const innerRemaining = scopedBytes.length - innerOffset;
  const innerLayers: Layer[] = [];
  let innerPayload: Uint8Array;

  if (depth + 1 >= MAX_IP_LAYERS) {
    notes.push(
      `GRE tunnel depth limit (${MAX_IP_LAYERS}) exceeded; remaining bytes kept as Payload.`,
    );
    innerPayload = scopedBytes.slice(innerOffset);
  } else if (protocolType === GRE_PROTOCOL_TEB) {
    if (innerRemaining < ETHERNET_HEADER_LENGTH) {
      notes.push(
        `Ethernet II frame after GRE (0x6558) is truncated (${innerRemaining} bytes); remaining bytes kept as Payload.`,
      );
      innerPayload = scopedBytes.slice(innerOffset);
    } else {
      innerPayload = decodeEthernetFrameAt(
        scopedBytes,
        innerOffset,
        innerLayers,
        notes,
        depth + 1,
      );
    }
  } else {
    innerPayload = decodeEtherTypeChain(
      scopedBytes,
      innerOffset,
      protocolType,
      innerLayers,
      notes,
      0,
      depth + 1,
      'gre',
    );
  }

  const expectedProto = greProtocolTypeForUpperLayer(innerLayers[0]?.type ?? null);
  const greLayer: GRELayer = {
    type: 'gre',
    checksumPresent,
    keyPresent,
    sequencePresent,
    version: autoValue(),
    protocolType:
      expectedProto !== null && protocolType === expectedProto
        ? autoValue()
        : manualValue(protocolType),
    checksum: checksumPresent ? checksumAutoOrManual : autoValue(),
    key,
    sequenceNumber,
  };

  decodedUpperLayers.push(greLayer, ...innerLayers);
  return innerPayload;
}

const MAX_VLAN_TAGS = 16;

type EtherTypeParentKind = 'ethernet' | 'gre';

function isVLANTpid(etherType: number): boolean {
  return (
    etherType === ETHERTYPE_VLAN ||
    etherType === ETHERTYPE_QINQ ||
    etherType === ETHERTYPE_QINQ_LEGACY
  );
}

function decodeEtherTypeChain(
  bytes: Uint8Array,
  offset: number,
  etherType: number,
  layers: Layer[],
  notes: string[],
  vlanDepth = 0,
  tunnelDepth = 0,
  parentKind: EtherTypeParentKind = 'ethernet',
): Uint8Array {
  const remaining = bytes.length - offset;

  if (isVLANTpid(etherType)) {
    if (vlanDepth >= MAX_VLAN_TAGS) {
      notes.push(
        `VLAN tag depth limit (${MAX_VLAN_TAGS} tags) exceeded; remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    if (remaining < VLAN_HEADER_LENGTH) {
      notes.push(
        `VLAN tag header (TPID 0x${etherType.toString(16).padStart(4, '0')}) is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }

    const tci = readUint16BE(bytes, offset);
    const pcp = (tci >>> 13) & 0x7;
    const dei = ((tci >>> 12) & 0x1) !== 0;
    const vid = tci & 0xfff;
    const innerEtherType = readUint16BE(bytes, offset + 2);

    const decodedUpperLayers: Layer[] = [];
    const payload = decodeEtherTypeChain(
      bytes,
      offset + VLAN_HEADER_LENGTH,
      innerEtherType,
      decodedUpperLayers,
      notes,
      vlanDepth + 1,
      tunnelDepth,
      parentKind,
    );

    const expectedInner = vlanInnerEtherTypeForUpperLayer(decodedUpperLayers[0]?.type ?? null);
    const vlanLayer: VLANLayer = {
      type: 'vlan',
      pcp,
      dei,
      vid,
      etherType:
        expectedInner !== null && innerEtherType === expectedInner
          ? autoValue()
          : manualValue(innerEtherType),
    };
    layers.push(vlanLayer, ...decodedUpperLayers);
    return payload;
  }

  const enclosing =
    vlanDepth > 0 ? 'VLAN tag' : parentKind === 'gre' ? 'GRE' : 'Ethernet II';

  if (etherType === ETHERTYPE_IPV4) {
    if (remaining < IPV4_HEADER_LENGTH) {
      notes.push(
        `IPv4 header after ${enclosing} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    if (tunnelDepth > 0) {
      const innerPayload = tryDecodeInnerIPv4(
        bytes,
        offset,
        remaining,
        layers,
        notes,
        tunnelDepth - 1,
        `after ${enclosing}`,
      );
      return innerPayload ?? bytes.slice(offset);
    }
    const version = bytes[offset] >>> 4;
    const ihl = bytes[offset] & 0x0f;
    if (version !== IPV4_VERSION || ihl < IPV4_IHL) {
      notes.push(
        `IPv4 header has Version=${version}, IHL=${ihl} (expected Version=4, IHL >= 5); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    const headerLength = ihl * 4;
    if (remaining < headerLength) {
      notes.push(
        `IPv4 header after ${enclosing} is truncated (${remaining} bytes available, IHL=${ihl} requires ${headerLength} bytes); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    return decodeIPv4Chain(bytes, offset, layers, notes);
  }

  if (etherType === ETHERTYPE_IPV6) {
    if (remaining < IPV6_HEADER_LENGTH) {
      notes.push(
        `IPv6 header after ${enclosing} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    if (tunnelDepth > 0) {
      const innerPayload = tryDecodeInnerIPv6(
        bytes,
        offset,
        remaining,
        layers,
        notes,
        tunnelDepth - 1,
        `after ${enclosing}`,
      );
      return innerPayload ?? bytes.slice(offset);
    }
    const version = bytes[offset] >>> 4;
    if (version !== IPV6_VERSION) {
      notes.push(
        `IPv6 header has Version=${version} (expected Version=6); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    return decodeIPv6Chain(bytes, offset, layers, notes);
  }

  if (etherType === ETHERTYPE_ARP) {
    if (remaining < ARP_HEADER_LENGTH) {
      notes.push(
        `ARP packet after ${enclosing} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return bytes.slice(offset);
    }
    layers.push(decodeARPAt(bytes, offset));
    const trailing = bytes.slice(offset + ARP_HEADER_LENGTH);
    if (trailing.length > 0) {
      notes.push(
        `Preserved ${trailing.length} trailing byte(s) after the 28-byte ARP header (e.g., Ethernet padding) in Payload.`,
      );
    }
    return trailing;
  }

  const label = vlanDepth === 0 && parentKind === 'gre' ? 'GRE Protocol Type' : 'EtherType';
  notes.push(
    `${label} 0x${etherType.toString(16).padStart(4, '0')} is not decoded into a layer; remaining bytes kept as Payload.`,
  );
  return bytes.slice(offset);
}

function decodeEthernetFrameAt(
  bytes: Uint8Array,
  offset: number,
  layers: Layer[],
  notes: string[],
  tunnelDepth = 0,
): Uint8Array {
  const dstMac = formatMac(bytes.subarray(offset, offset + 6));
  const srcMac = formatMac(bytes.subarray(offset + 6, offset + 12));
  const etherType = readUint16BE(bytes, offset + 12);

  const decodedUpperLayers: Layer[] = [];
  const payload = decodeEtherTypeChain(
    bytes,
    offset + ETHERNET_HEADER_LENGTH,
    etherType,
    decodedUpperLayers,
    notes,
    0,
    tunnelDepth,
    'ethernet',
  );

  const expectedEthEtherType = ethernetEtherTypeForUpperLayers(
    decodedUpperLayers[0]?.type ?? null,
    decodedUpperLayers[1]?.type ?? null,
  );
  const ethLayer: EthernetLayer = {
    type: 'ethernet',
    dstMac,
    srcMac,
    etherType:
      expectedEthEtherType !== null && etherType === expectedEthEtherType
        ? autoValue()
        : manualValue(etherType),
  };
  layers.push(ethLayer, ...decodedUpperLayers);
  return payload;
}

/**
 * Decodes raw packet bytes into a stack of tsumiki Layer objects and a Payload.
 * Preserves auto vs. manual field status so re-encoding reproduces the exact input bytes.
 */
export function decodePacket(
  bytes: Uint8Array,
  startLayer: DecodeStartLayer = 'ethernet',
): Result<DecodedPacket> {
  if (bytes.length === 0) {
    return err('Input packet is empty. Paste hexadecimal packet bytes to decode.');
  }

  const layers: Layer[] = [];
  const notes: string[] = [];

  if (startLayer === 'ipv4') {
    if (bytes.length < IPV4_HEADER_LENGTH) {
      return err(
        `Packet is too short for an IPv4 header (need at least ${IPV4_HEADER_LENGTH} bytes, got ${bytes.length}).`,
      );
    }
    const version = bytes[0] >>> 4;
    const ihl = bytes[0] & 0x0f;
    if (version !== IPV4_VERSION) {
      return err(`Expected IPv4 (Version=4), but got Version=${version}.`);
    }
    if (ihl < IPV4_IHL) {
      return err(
        `IPv4 header has invalid IHL=${ihl} (minimum is 5 / 20 bytes per RFC 791 §3.1).`,
      );
    }
    const headerLength = ihl * 4;
    if (bytes.length < headerLength) {
      return err(
        `Packet is too short for IPv4 header with IHL=${ihl} (need at least ${headerLength} bytes, got ${bytes.length}).`,
      );
    }

    const payload = decodeIPv4Chain(bytes, 0, layers, notes);
    return ok({ layers, payload, notes });
  }

  if (startLayer === 'ipv6') {
    if (bytes.length < IPV6_HEADER_LENGTH) {
      return err(
        `Packet is too short for an IPv6 header (need at least ${IPV6_HEADER_LENGTH} bytes, got ${bytes.length}).`,
      );
    }
    const version = bytes[0] >>> 4;
    if (version !== IPV6_VERSION) {
      return err(`Expected IPv6 (Version=6), but got Version=${version}.`);
    }

    const payload = decodeIPv6Chain(bytes, 0, layers, notes);
    return ok({ layers, payload, notes });
  }

  // Ethernet II start layer
  if (bytes.length < ETHERNET_HEADER_LENGTH) {
    return err(
      `Packet is too short for an Ethernet II header (need at least ${ETHERNET_HEADER_LENGTH} bytes, got ${bytes.length}).`,
    );
  }

  const payload = decodeEthernetFrameAt(bytes, 0, layers, notes, 0);
  return ok({ layers, payload, notes });
}

export type PrintableUtf8Result =
  | { readonly printable: true; readonly text: string }
  | { readonly printable: false };

// Reject C0/DEL control chars (except \t, \n, \r) and UTF-8 BOM so binary payloads stay in Hex mode
const NON_PRINTABLE_OR_BOM_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\ufeff]/;

/**
 * Checks whether decoded payload bytes can be safely edited in Text (UTF-8) mode
 * without hiding binary control characters or a leading BOM.
 */
export function detectPrintableUtf8(bytes: Uint8Array): PrintableUtf8Result {
  if (bytes.length === 0) {
    return { printable: true, text: '' };
  }
  const decoded = decodeUtf8Strict(bytes);
  if (!decoded.ok) {
    return { printable: false };
  }
  if (NON_PRINTABLE_OR_BOM_PATTERN.test(decoded.value)) {
    return { printable: false };
  }
  return { printable: true, text: decoded.value };
}
