import type { Layer } from './layers/types';

/** Classic libpcap global header length (24 bytes) */
export const PCAP_GLOBAL_HEADER_LENGTH = 24;
/** Classic libpcap packet record header length (16 bytes) */
export const PCAP_PACKET_HEADER_LENGTH = 16;
/** Standard microsecond-resolution libpcap magic number */
export const PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4;
export const PCAP_VERSION_MAJOR = 2;
export const PCAP_VERSION_MINOR = 4;
export const PCAP_DEFAULT_SNAPLEN = 65535;

/** Link-layer header types defined by tcpdump / libpcap */
export const LINKTYPE_ETHERNET = 1;
export const LINKTYPE_RAW = 101;
export const LINKTYPE_USER0 = 147;

export interface BuildPcapOptions {
  /** Link-layer header type (e.g., LINKTYPE_ETHERNET=1, LINKTYPE_RAW=101) */
  readonly linkType?: number;
  /** Capture timestamp in milliseconds since Unix epoch */
  readonly timestampMs?: number;
}

export interface PcapPacketRecord {
  readonly bytes: Uint8Array;
  /** Capture timestamp in milliseconds since Unix epoch */
  readonly timestampMs: number;
}

export interface BuildMultiPcapOptions {
  /** Link-layer header type (e.g., LINKTYPE_ETHERNET=1, LINKTYPE_RAW=101) */
  readonly linkType?: number;
}

/**
 * Selects the most appropriate libpcap link-layer header type from the outermost layer.
 * - Ethernet II -> LINKTYPE_ETHERNET (1)
 * - IPv4 / IPv6 -> LINKTYPE_RAW (101)
 * - Other/Empty -> LINKTYPE_USER0 (147)
 */
export function selectPcapLinkType(layers: readonly Layer[]): number {
  const first = layers[0];
  if (!first) {
    return LINKTYPE_USER0;
  }
  if (first.type === 'ethernet') {
    return LINKTYPE_ETHERNET;
  }
  if (first.type === 'ipv4' || first.type === 'ipv6') {
    return LINKTYPE_RAW;
  }
  return LINKTYPE_USER0;
}

/**
 * Encodes one or more packets with per-packet timestamps into classic libpcap
 * format (little-endian, v2.4) compatible with Wireshark and tcpdump.
 */
export function buildMultiPcap(
  packets: readonly PcapPacketRecord[],
  options: BuildMultiPcapOptions = {},
): Uint8Array {
  const linkType = options.linkType ?? LINKTYPE_ETHERNET;
  let snaplen = PCAP_DEFAULT_SNAPLEN;
  let totalLength = PCAP_GLOBAL_HEADER_LENGTH;

  for (const packet of packets) {
    if (packet.bytes.length > snaplen) {
      snaplen = packet.bytes.length;
    }
    totalLength += PCAP_PACKET_HEADER_LENGTH + packet.bytes.length;
  }

  const buffer = new Uint8Array(totalLength);
  const view = new DataView(buffer.buffer);

  // Global Header (24 bytes, little-endian)
  view.setUint32(0, PCAP_MAGIC_MICROSECONDS, true);
  view.setUint16(4, PCAP_VERSION_MAJOR, true);
  view.setUint16(6, PCAP_VERSION_MINOR, true);
  view.setInt32(8, 0, true); // thiszone
  view.setUint32(12, 0, true); // sigfigs
  view.setUint32(16, snaplen, true);
  view.setUint32(20, linkType >>> 0, true);

  let offset = PCAP_GLOBAL_HEADER_LENGTH;
  for (const packet of packets) {
    const rawMs = packet.timestampMs;
    const safeMs = Number.isFinite(rawMs) && rawMs > 0 ? rawMs : 0;
    const tsSec = Math.min(0xffffffff, Math.floor(safeMs / 1000));
    const tsUsec = Math.min(999999, Math.floor((safeMs % 1000) * 1000));

    // Packet Record Header (16 bytes, little-endian)
    view.setUint32(offset, tsSec, true);
    view.setUint32(offset + 4, tsUsec, true);
    view.setUint32(offset + 8, packet.bytes.length, true); // incl_len
    view.setUint32(offset + 12, packet.bytes.length, true); // orig_len
    offset += PCAP_PACKET_HEADER_LENGTH;

    buffer.set(packet.bytes, offset);
    offset += packet.bytes.length;
  }

  return buffer;
}

/**
 * Encodes a single packet into classic libpcap format (little-endian, v2.4)
 * compatible with Wireshark and tcpdump.
 */
export function buildPcap(packetBytes: Uint8Array, options: BuildPcapOptions = {}): Uint8Array {
  return buildMultiPcap(
    [{ bytes: packetBytes, timestampMs: options.timestampMs ?? 0 }],
    { linkType: options.linkType },
  );
}
