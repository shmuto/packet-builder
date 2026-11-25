import {
  decodeUtf8Strict,
  formatIPv4,
  formatMac,
  readUint16BE,
  readUint32BE,
} from './bytes';
import { internetChecksum, ipv4PseudoHeaderChecksum } from './checksum';
import {
  ARP_HEADER_LENGTH,
  ARP_HLEN_ETHERNET,
  ARP_HTYPE_ETHERNET,
  ARP_PLEN_IPV4,
  ARP_PTYPE_IPV4,
} from './layers/arp';
import {
  ETHERNET_HEADER_LENGTH,
  ETHERTYPE_ARP,
  ETHERTYPE_IPV4,
} from './layers/ethernet';
import { ICMP_HEADER_LENGTH } from './layers/icmp';
import {
  IP_PROTOCOL_ICMP,
  IP_PROTOCOL_TCP,
  IP_PROTOCOL_UDP,
  IPV4_HEADER_LENGTH,
  IPV4_IHL,
  IPV4_VERSION,
} from './layers/ipv4';
import { TCP_DEFAULT_DATA_OFFSET, TCP_HEADER_LENGTH } from './layers/tcp';
import {
  autoValue,
  manualValue,
  type ARPLayer,
  type EthernetLayer,
  type ICMPLayer,
  type IPv4Layer,
  type Layer,
  type TCPLayer,
  type UDPLayer,
} from './layers/types';
import { UDP_HEADER_LENGTH } from './layers/udp';
import { err, ok, type Result } from './result';

export type DecodeStartLayer = 'ethernet' | 'ipv4';

export interface DecodedPacket {
  readonly layers: readonly Layer[];
  readonly payload: Uint8Array;
  /** Informational notes about unsupported/truncated or non-base header fields */
  readonly notes: readonly string[];
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

function decodeUDPAt(
  bytes: Uint8Array,
  offset: number,
  srcIpBytes: Uint8Array,
  dstIpBytes: Uint8Array,
): { layer: UDPLayer; payload: Uint8Array } {
  const srcPort = readUint16BE(bytes, offset);
  const dstPort = readUint16BE(bytes, offset + 2);
  const length = readUint16BE(bytes, offset + 4);
  const checksum = readUint16BE(bytes, offset + 6);

  const actualLength = bytes.length - offset;
  const segmentCopy = new Uint8Array(bytes.subarray(offset));
  segmentCopy[6] = 0;
  segmentCopy[7] = 0;

  const csumRes = ipv4PseudoHeaderChecksum({
    srcIp: srcIpBytes,
    dstIp: dstIpBytes,
    protocol: IP_PROTOCOL_UDP,
    segment: segmentCopy,
  });
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
  srcIpBytes: Uint8Array,
  dstIpBytes: Uint8Array,
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
  const csumRes = ipv4PseudoHeaderChecksum({
    srcIp: srcIpBytes,
    dstIp: dstIpBytes,
    protocol: IP_PROTOCOL_TCP,
    segment: segmentCopy,
  });
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

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

function decodeIPv4Chain(
  bytes: Uint8Array,
  offset: number,
  layers: Layer[],
  notes: string[],
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

  const actualTotalLength = bytes.length - offset;
  let scopedBytes = bytes;
  let effectiveTotalLength = actualTotalLength;

  if (totalLength >= IPV4_HEADER_LENGTH && totalLength < actualTotalLength) {
    const trailing = bytes.subarray(offset + totalLength);
    if (isAllZero(trailing)) {
      // Standard IEEE 802.3 Ethernet zero-padding: scope upper-layer decoding & checksums
      // strictly to IPv4 Total Length per RFC 768 / RFC 9293 §3.1
      scopedBytes = bytes.subarray(0, offset + totalLength);
      effectiveTotalLength = totalLength;
      notes.push(
        `Stripped ${trailing.length} trailing zero byte(s) of Ethernet padding beyond IPv4 Total Length (${totalLength}).`,
      );
    } else {
      notes.push(
        `IPv4 Total Length (${totalLength}) is smaller than remaining bytes (${actualTotalLength}) with non-zero trailing data; trailing bytes are preserved in Payload.`,
      );
    }
  }

  const headerCopy = new Uint8Array(scopedBytes.subarray(offset, offset + IPV4_HEADER_LENGTH));
  headerCopy[10] = 0;
  headerCopy[11] = 0;
  const computedHeaderChecksum = internetChecksum(headerCopy);

  const upperOffset = offset + IPV4_HEADER_LENGTH;
  const upperRemaining = scopedBytes.length - upperOffset;

  let decodedUpperLayer: Layer | null = null;
  let payload: Uint8Array = scopedBytes.slice(upperOffset);

  if (fragmentOffset !== 0) {
    // RFC 791: non-initial fragments carry continuation payload rather than an L4 header
    notes.push(
      `Non-initial IPv4 fragment (Fragment Offset = ${fragmentOffset}); upper-layer header is not decoded per RFC 791 and remaining bytes are kept as Payload.`,
    );
  } else if (protocol === IP_PROTOCOL_ICMP && upperRemaining >= ICMP_HEADER_LENGTH) {
    const res = decodeICMPAt(scopedBytes, upperOffset);
    decodedUpperLayer = res.layer;
    payload = res.payload;
  } else if (protocol === IP_PROTOCOL_UDP && upperRemaining >= UDP_HEADER_LENGTH) {
    const res = decodeUDPAt(scopedBytes, upperOffset, srcIpBytes, dstIpBytes);
    decodedUpperLayer = res.layer;
    payload = res.payload;
  } else if (protocol === IP_PROTOCOL_TCP && upperRemaining >= TCP_HEADER_LENGTH) {
    const res = decodeTCPAt(scopedBytes, upperOffset, srcIpBytes, dstIpBytes, notes);
    decodedUpperLayer = res.layer;
    payload = res.payload;
  } else if (
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
    protocol: decodedUpperLayer !== null ? autoValue() : manualValue(protocol),
    headerChecksum:
      headerChecksum === computedHeaderChecksum ? autoValue() : manualValue(headerChecksum),
    srcIp: formatIPv4(srcIpBytes),
    dstIp: formatIPv4(dstIpBytes),
  };

  layers.push(ipv4Layer);
  if (decodedUpperLayer !== null) {
    layers.push(decodedUpperLayer);
  }
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
    etherType: canDecodeIPv4 || canDecodeARP ? autoValue() : manualValue(etherType),
  };
  layers.push(ethLayer);

  if (canDecodeIPv4) {
    const payload = decodeIPv4Chain(bytes, afterEth, layers, notes);
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
