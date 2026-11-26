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
  ETHERTYPE_ARP,
  ETHERTYPE_IPV4,
  ETHERTYPE_IPV6,
} from './layers/ethernet';
import { ICMP_HEADER_LENGTH } from './layers/icmp';
import {
  IP_PROTOCOL_ICMP,
  IP_PROTOCOL_IPIP,
  IP_PROTOCOL_IPV6,
  IP_PROTOCOL_TCP,
  IP_PROTOCOL_UDP,
  IPV4_HEADER_LENGTH,
  IPV4_IHL,
  IPV4_VERSION,
} from './layers/ipv4';
import { IPV6_HEADER_LENGTH, IPV6_VERSION } from './layers/ipv6';
import { TCP_DEFAULT_DATA_OFFSET, TCP_HEADER_LENGTH } from './layers/tcp';
import {
  autoValue,
  manualValue,
  type ARPLayer,
  type BGPLayer,
  type BGPMessageType,
  type EthernetLayer,
  type ICMPLayer,
  type IPv4Layer,
  type IPv6Layer,
  type Layer,
  type TCPLayer,
  type UDPLayer,
} from './layers/types';
import { UDP_HEADER_LENGTH } from './layers/udp';
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

  if (dataOffset > TCP_DEFAULT_DATA_OFFSET) {
    notes.push(
      `TCP Data Offset is ${dataOffset} (${dataOffset * 4} bytes with options); bytes beyond the 20-byte base header are placed in Payload.`,
    );
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
      dataOffset:
        dataOffset === TCP_DEFAULT_DATA_OFFSET ? autoValue() : manualValue(dataOffset),
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
    },
    payload: bytes.slice(offset + TCP_HEADER_LENGTH),
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
    const tcpOptionsBytes = Math.max(
      0,
      (res.layer.dataOffset.value - TCP_DEFAULT_DATA_OFFSET) * 4,
    );
    if (res.layer.dataOffset.value < TCP_DEFAULT_DATA_OFFSET) {
      notes.push(
        `TCP segment on port 179 has invalid Data Offset (${res.layer.dataOffset.value}); BGP-4 decoding skipped.`,
      );
    } else if (res.payload.length > tcpOptionsBytes) {
      notes.push(
        `TCP options present on port 179 (Data Offset = ${res.layer.dataOffset.value}); BGP-4 decoding skipped so TCP options and application bytes remain preserved in Payload.`,
      );
    }
  }
  return res.payload;
}

function tryDecodeInnerIPv4(
  scopedBytes: Uint8Array,
  upperOffset: number,
  upperRemaining: number,
  decodedUpperLayers: Layer[],
  notes: string[],
  depth: number,
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
  if (innerVersion !== IPV4_VERSION || innerIhl !== IPV4_IHL) {
    notes.push(
      `Inner IPv4 header (Protocol ${IP_PROTOCOL_IPIP}) has Version=${innerVersion}, IHL=${innerIhl} (only Version=4, IHL=5 supported); remaining bytes kept as Payload.`,
    );
    return null;
  }
  if (innerTotalLength >= IPV4_HEADER_LENGTH && innerTotalLength < upperRemaining) {
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
      `Inner IPv6 header (Protocol ${IP_PROTOCOL_IPV6}) has Version=${innerVersion} (expected Version=6); remaining bytes kept as Payload.`,
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

  if (depth === 0 && totalLength >= IPV4_HEADER_LENGTH && totalLength < actualTotalLength) {
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

  const headerCopy = new Uint8Array(scopedBytes.subarray(offset, offset + IPV4_HEADER_LENGTH));
  headerCopy[10] = 0;
  headerCopy[11] = 0;
  const computedHeaderChecksum = internetChecksum(headerCopy);

  const upperOffset = offset + IPV4_HEADER_LENGTH;
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
  } else if (protocol === IP_PROTOCOL_ICMP && upperRemaining >= ICMP_HEADER_LENGTH) {
    const res = decodeICMPAt(scopedBytes, upperOffset);
    decodedUpperLayers.push(res.layer);
    payload = res.payload;
  } else if (protocol === IP_PROTOCOL_UDP && upperRemaining >= UDP_HEADER_LENGTH) {
    const res = decodeUDPAt(scopedBytes, upperOffset, ipInfo);
    decodedUpperLayers.push(res.layer);
    payload = res.payload;
  } else if (protocol === IP_PROTOCOL_TCP && upperRemaining >= TCP_HEADER_LENGTH) {
    payload = decodeTCPAndBGPAt(scopedBytes, upperOffset, ipInfo, decodedUpperLayers, notes);
  } else if (
    protocol === IP_PROTOCOL_IPIP ||
    protocol === IP_PROTOCOL_IPV6 ||
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

  if (depth === 0 && payloadLength < actualPayloadLength) {
    const trailing = bytes.subarray(upperOffset + payloadLength);
    // Per RFC 8200 §3 / §8.1, upper-layer segments and checksums are bounded by IPv6 Payload Length.
    scopedBytes = bytes.subarray(0, upperOffset + payloadLength);
    effectivePayloadLength = payloadLength;
    if (isAllZero(trailing)) {
      notes.push(
        `Stripped ${trailing.length} trailing zero byte(s) of Ethernet padding beyond IPv6 Payload Length (${payloadLength}).`,
      );
    } else {
      notes.push(
        `Stripped ${trailing.length} trailing non-zero byte(s) of Ethernet padding/trailer beyond IPv6 Payload Length (${payloadLength}) per RFC 8200 §3; re-encoded bytes will omit these trailing bytes.`,
      );
    }
  }

  const upperRemaining = scopedBytes.length - upperOffset;
  const decodedUpperLayers: Layer[] = [];
  let payload: Uint8Array = scopedBytes.slice(upperOffset);

  if (Object.prototype.hasOwnProperty.call(IPV6_EXTENSION_HEADER_NAMES, nextHeader)) {
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
  } else if (nextHeader === IP_PROTOCOL_UDP && upperRemaining >= UDP_HEADER_LENGTH) {
    const res = decodeUDPAt(scopedBytes, upperOffset, ipInfo);
    decodedUpperLayers.push(res.layer);
    payload = res.payload;
  } else if (nextHeader === IP_PROTOCOL_TCP && upperRemaining >= TCP_HEADER_LENGTH) {
    payload = decodeTCPAndBGPAt(scopedBytes, upperOffset, ipInfo, decodedUpperLayers, notes);
  } else if (
    nextHeader === IP_PROTOCOL_IPIP ||
    nextHeader === IP_PROTOCOL_IPV6 ||
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
    // In Raw IPv4 mode the outermost layer itself must be a supported IHL=5 IPv4 header;
    // in Ethernet mode, Ethernet II still decodes validly and keeps unsupported IPv4 options as Payload.
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
    if (ihl !== IPV4_IHL) {
      return err(
        `Only IPv4 headers without options (IHL=5 / 20 bytes) are supported (got IHL=${ihl}).`,
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

  const dstMac = formatMac(bytes.subarray(0, 6));
  const srcMac = formatMac(bytes.subarray(6, 12));
  const etherType = readUint16BE(bytes, 12);
  const afterEth = ETHERNET_HEADER_LENGTH;
  const remaining = bytes.length - afterEth;

  let canDecodeIPv4 = false;
  let canDecodeIPv6 = false;
  let canDecodeARP = false;

  if (etherType === ETHERTYPE_IPV4) {
    if (remaining < IPV4_HEADER_LENGTH) {
      notes.push(
        `IPv4 header after Ethernet II is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
    } else {
      const version = bytes[afterEth] >>> 4;
      const ihl = bytes[afterEth] & 0x0f;
      if (version === IPV4_VERSION && ihl === IPV4_IHL) {
        canDecodeIPv4 = true;
      } else {
        notes.push(
          `IPv4 header has Version=${version}, IHL=${ihl} (only Version=4, IHL=5 supported); remaining bytes kept as Payload.`,
        );
      }
    }
  } else if (etherType === ETHERTYPE_IPV6) {
    if (remaining < IPV6_HEADER_LENGTH) {
      notes.push(
        `IPv6 header after Ethernet II is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
    } else {
      const version = bytes[afterEth] >>> 4;
      if (version === IPV6_VERSION) {
        canDecodeIPv6 = true;
      } else {
        notes.push(
          `IPv6 header has Version=${version} (expected Version=6); remaining bytes kept as Payload.`,
        );
      }
    }
  } else if (etherType === ETHERTYPE_ARP) {
    if (remaining >= ARP_HEADER_LENGTH) {
      canDecodeARP = true;
    } else {
      notes.push(
        `ARP packet after Ethernet II is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
    }
  } else {
    notes.push(
      `EtherType 0x${etherType.toString(16).padStart(4, '0')} is not decoded into a layer; remaining bytes kept as Payload.`,
    );
  }

  const ethLayer: EthernetLayer = {
    type: 'ethernet',
    dstMac,
    srcMac,
    etherType:
      canDecodeIPv4 || canDecodeIPv6 || canDecodeARP ? autoValue() : manualValue(etherType),
  };
  layers.push(ethLayer);

  if (canDecodeIPv4) {
    const payload = decodeIPv4Chain(bytes, afterEth, layers, notes);
    return ok({ layers, payload, notes });
  }

  if (canDecodeIPv6) {
    const payload = decodeIPv6Chain(bytes, afterEth, layers, notes);
    return ok({ layers, payload, notes });
  }

  if (canDecodeARP) {
    layers.push(decodeARPAt(bytes, afterEth));
    const trailing = bytes.slice(afterEth + ARP_HEADER_LENGTH);
    if (trailing.length > 0) {
      notes.push(
        `Preserved ${trailing.length} trailing byte(s) after the 28-byte ARP header (e.g., Ethernet padding) in Payload.`,
      );
    }
    return ok({ layers, payload: trailing, notes });
  }

  return ok({ layers, payload: bytes.slice(afterEth), notes });
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
