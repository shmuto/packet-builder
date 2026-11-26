import { describe, expect, it } from 'vitest';
import {
  buildMultiPcap,
  buildPcap,
  LINKTYPE_ETHERNET,
  LINKTYPE_RAW,
  LINKTYPE_USER0,
  PCAP_GLOBAL_HEADER_LENGTH,
  PCAP_MAGIC_MICROSECONDS,
  PCAP_PACKET_HEADER_LENGTH,
  selectPcapLinkType,
} from './pcap';
import { autoValue, type Layer } from './layers/types';

const SAMPLE_ETH: Layer = {
  type: 'ethernet',
  dstMac: '00:00:5e:00:53:02',
  srcMac: '00:00:5e:00:53:01',
  etherType: autoValue(),
};
const SAMPLE_IPV4: Layer = {
  type: 'ipv4',
  ihl: autoValue(),
  tos: 0,
  totalLength: autoValue(),
  identification: 1,
  flags: { reserved: false, df: true, mf: false },
  fragmentOffset: 0,
  ttl: 64,
  protocol: autoValue(),
  headerChecksum: autoValue(),
  srcIp: '192.0.2.1',
  dstIp: '192.0.2.2',
};
const SAMPLE_IPV6: Layer = {
  type: 'ipv6',
  trafficClass: 0,
  flowLabel: 0,
  payloadLength: autoValue(),
  nextHeader: autoValue(),
  hopLimit: 64,
  srcIp: '2001:db8::1',
  dstIp: '2001:db8::2',
};
const SAMPLE_TCP: Layer = {
  type: 'tcp',
  srcPort: 49152,
  dstPort: 179,
  seqNumber: 1,
  ackNumber: 0,
  dataOffset: autoValue(),
  flags: { cwr: false, ece: false, urg: false, ack: false, psh: false, rst: false, syn: true, fin: false },
  windowSize: 65535,
  checksum: autoValue(),
  urgentPointer: 0,
  options: [],
};

describe('selectPcapLinkType', () => {
  it('selects link type based on the outermost layer', () => {
    expect(selectPcapLinkType([SAMPLE_ETH, SAMPLE_IPV4])).toBe(LINKTYPE_ETHERNET);
    expect(selectPcapLinkType([SAMPLE_IPV4, SAMPLE_TCP])).toBe(LINKTYPE_RAW);
    expect(selectPcapLinkType([SAMPLE_IPV6, SAMPLE_TCP])).toBe(LINKTYPE_RAW);
    expect(selectPcapLinkType([SAMPLE_TCP])).toBe(LINKTYPE_USER0);
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

describe('buildMultiPcap', () => {
  it('writes multiple packets with independent timestamps and computes snaplen across all packets', () => {
    const p1 = new Uint8Array([0x01, 0x02, 0x03]);
    const p2 = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    const pcap = buildMultiPcap(
      [
        { bytes: p1, timestampMs: 1_700_000_000_010 },
        { bytes: p2, timestampMs: 1_700_000_001_500 },
      ],
      { linkType: LINKTYPE_ETHERNET },
    );

    expect(pcap.length).toBe(
      PCAP_GLOBAL_HEADER_LENGTH +
        PCAP_PACKET_HEADER_LENGTH +
        p1.length +
        PCAP_PACKET_HEADER_LENGTH +
        p2.length,
    );

    const view = new DataView(pcap.buffer);
    expect(view.getUint32(0, true)).toBe(PCAP_MAGIC_MICROSECONDS);
    expect(view.getUint32(20, true)).toBe(LINKTYPE_ETHERNET);

    // Record 1
    expect(view.getUint32(24, true)).toBe(1_700_000_000);
    expect(view.getUint32(28, true)).toBe(10_000);
    expect(view.getUint32(32, true)).toBe(3);
    expect(pcap.slice(40, 43)).toEqual(p1);

    // Record 2
    const rec2 = 43;
    expect(view.getUint32(rec2, true)).toBe(1_700_000_001);
    expect(view.getUint32(rec2 + 4, true)).toBe(500_000);
    expect(view.getUint32(rec2 + 8, true)).toBe(5);
    expect(pcap.slice(rec2 + 16, rec2 + 21)).toEqual(p2);
  });

  it('produces a valid 24-byte global header when given zero packets', () => {
    const empty = buildMultiPcap([]);
    expect(empty.length).toBe(PCAP_GLOBAL_HEADER_LENGTH);
    expect(new DataView(empty.buffer).getUint32(0, true)).toBe(PCAP_MAGIC_MICROSECONDS);
  });
});

