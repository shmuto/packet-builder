import { describe, expect, it } from 'vitest';
import {
  buildPcap,
  LINKTYPE_ETHERNET,
  LINKTYPE_RAW,
  LINKTYPE_USER0,
  PCAP_GLOBAL_HEADER_LENGTH,
  PCAP_MAGIC_MICROSECONDS,
  PCAP_PACKET_HEADER_LENGTH,
  selectPcapLinkType,
} from './pcap';
import { createDefaultEthernet, createDefaultIPv4, createDefaultUDP } from './presets';

describe('selectPcapLinkType', () => {
  it('selects link type based on the outermost layer', () => {
    expect(selectPcapLinkType([createDefaultEthernet(), createDefaultIPv4()])).toBe(
      LINKTYPE_ETHERNET,
    );
    expect(selectPcapLinkType([createDefaultIPv4(), createDefaultUDP()])).toBe(LINKTYPE_RAW);
    expect(selectPcapLinkType([createDefaultUDP()])).toBe(LINKTYPE_USER0);
    expect(selectPcapLinkType([])).toBe(LINKTYPE_USER0);
  });
});

describe('buildPcap', () => {
  it('writes a valid 24-byte global header, 16-byte record header, and packet payload', () => {
    const packet = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01]);
    const pcap = buildPcap(packet, {
      linkType: LINKTYPE_ETHERNET,
      timestampMs: 1_700_000_000_250,
    });

    expect(pcap.length).toBe(PCAP_GLOBAL_HEADER_LENGTH + PCAP_PACKET_HEADER_LENGTH + 5);

    const view = new DataView(pcap.buffer);
    // Global header (little-endian)
    expect(view.getUint32(0, true)).toBe(PCAP_MAGIC_MICROSECONDS);
    expect(view.getUint16(4, true)).toBe(2);
    expect(view.getUint16(6, true)).toBe(4);
    expect(view.getInt32(8, true)).toBe(0);
    expect(view.getUint32(12, true)).toBe(0);
    expect(view.getUint32(16, true)).toBe(65535);
    expect(view.getUint32(20, true)).toBe(LINKTYPE_ETHERNET);

    // Packet record header
    expect(view.getUint32(24, true)).toBe(1_700_000_000);
    expect(view.getUint32(28, true)).toBe(250_000);
    expect(view.getUint32(32, true)).toBe(5);
    expect(view.getUint32(36, true)).toBe(5);

    // Packet payload
    expect(pcap.slice(40)).toEqual(packet);
  });

  it('handles empty packets, packets larger than 65535 bytes, and invalid timestamps safely', () => {
    const emptyPcap = buildPcap(new Uint8Array(0), {
      linkType: LINKTYPE_RAW,
      timestampMs: -100,
    });
    expect(emptyPcap.length).toBe(40);
    const emptyView = new DataView(emptyPcap.buffer);
    expect(emptyView.getUint32(20, true)).toBe(LINKTYPE_RAW);
    expect(emptyView.getUint32(24, true)).toBe(0);
    expect(emptyView.getUint32(28, true)).toBe(0);
    expect(emptyView.getUint32(32, true)).toBe(0);
    expect(emptyView.getUint32(36, true)).toBe(0);

    // Ethernet (14B) + max IPv4 (65535B) = 65549B -> snaplen expands to fit without truncation
    const maxEthIp = new Uint8Array(65549);
    const largePcap = buildPcap(maxEthIp, { timestampMs: Number.NaN });
    const largeView = new DataView(largePcap.buffer);
    expect(largeView.getUint32(16, true)).toBe(65549);
    expect(largeView.getUint32(32, true)).toBe(65549);
    expect(largeView.getUint32(36, true)).toBe(65549);
  });
});
