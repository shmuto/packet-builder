import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from './bytes';
import { autoValue, type FieldSpan, type Layer } from './layers/types';
import { buildPacket } from './packet';
import {
  createDefaultARP,
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultICMP,
  createDefaultICMPv6,
  createDefaultIPv4,
  createDefaultIPv6,
  createDefaultTCP,
  createDefaultUDP,
} from './presets';

/** FieldSpan[] が 0 〜 totalBits まで隙間なく・重なりなく覆っていることを検証する */
function expectExactBitCoverage(spans: readonly FieldSpan[], totalBytes: number): void {
  let cursor = 0;
  for (const span of spans) {
    expect(span.bitLength).toBeGreaterThan(0);
    expect(span.bitOffset).toBe(cursor);
    cursor += span.bitLength;
  }
  expect(cursor).toBe(totalBytes * 8);
}

describe('buildPacket', () => {
  it('既知の Ethernet II + IPv4 + UDP + "Hello" パケットとバイト単位で完全一致する', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv4(),
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
    ];

    const result = buildPacket(layers, encodeUtf8('Hello'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
      // IPv4 (20B): TotalLen=33(0x0021), ID=0x1234, DF=0x4000, TTL=64, Proto=17, Checksum=0xa744
      0x45, 0x00, 0x00, 0x21,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x11, 0xa7, 0x44,
      0xc0, 0xa8, 0x00, 0x01,
      0xc0, 0xa8, 0x00, 0x02,
      // UDP (8B): 12345 -> 80, Len=13(0x000d), Checksum=0x2a25
      0x30, 0x39, 0x00, 0x50,
      0x00, 0x0d, 0x2a, 0x25,
      // Payload ("Hello")
      0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ]);

    expect(result.bytes).toEqual(expected);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('既知の Ethernet II + IPv4 + TCP SYN（空ペイロード）とバイト単位で完全一致する', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv4(),
      createDefaultTCP(),
    ];

    const result = buildPacket(layers, new Uint8Array(0));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
      // IPv4 (20B): TotalLen=40(0x0028), Proto=6, Checksum=0xa748
      0x45, 0x00, 0x00, 0x28,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x06, 0xa7, 0x48,
      0xc0, 0xa8, 0x00, 0x01,
      0xc0, 0xa8, 0x00, 0x02,
      // TCP (20B): 54321 -> 443, Seq=1000, Ack=0, DataOffset=5, SYN, Win=65535, Checksum=0x54ba
      0xd4, 0x31, 0x01, 0xbb,
      0x00, 0x00, 0x03, 0xe8,
      0x00, 0x00, 0x00, 0x00,
      0x50, 0x02, 0xff, 0xff,
      0x54, 0xba, 0x00, 0x00,
    ]);

    expect(result.bytes).toEqual(expected);
    expectExactBitCoverage(result.spans, expected.length);
    // ペイロード 0 バイト時は payload の span を含まない
    expect(result.spans.some((s) => s.section === 'payload')).toBe(false);
  });

  it('既知の Ethernet II + IPv4 + ICMP Echo Request + "ping" とバイト単位で完全一致する', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv4(),
      createDefaultICMP(),
    ];

    const result = buildPacket(layers, encodeUtf8('ping'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
      // IPv4 (20B): TotalLen=32(0x0020), Proto=1, Checksum=0xa755
      0x45, 0x00, 0x00, 0x20,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x01, 0xa7, 0x55,
      0xc0, 0xa8, 0x00, 0x01,
      0xc0, 0xa8, 0x00, 0x02,
      // ICMP (8B): Type=8, Code=0, Checksum=0x192d, ID=1, Seq=1
      0x08, 0x00, 0x19, 0x2d,
      0x00, 0x01, 0x00, 0x01,
      // Payload ("ping")
      0x70, 0x69, 0x6e, 0x67,
    ]);

    expect(result.bytes).toEqual(expected);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('サブバイトのフィールド（IPv4 Version/IHL/Flags/FragmentOffset, TCP DataOffset/Reserved/Flags）のビット範囲が正確である', () => {
    const result = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
      new Uint8Array(0),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const findSpan = (layerType: string, fieldId: string) =>
      result.spans.find((s) => s.layerType === layerType && s.fieldId === fieldId);

    // Ethernet 14B = 112bit の直後から IPv4 開始
    expect(findSpan('ipv4', 'version')).toMatchObject({ bitOffset: 112, bitLength: 4 });
    expect(findSpan('ipv4', 'ihl')).toMatchObject({ bitOffset: 116, bitLength: 4 });
    expect(findSpan('ipv4', 'flags')).toMatchObject({ bitOffset: 160, bitLength: 3 });
    expect(findSpan('ipv4', 'fragmentOffset')).toMatchObject({ bitOffset: 163, bitLength: 13 });

    // Ethernet(14B) + IPv4(20B) = 34B = 272bit の直後から TCP 開始
    expect(findSpan('tcp', 'dataOffset')).toMatchObject({ bitOffset: 272 + 96, bitLength: 4 });
    expect(findSpan('tcp', 'reserved')).toMatchObject({ bitOffset: 272 + 100, bitLength: 4 });
    expect(findSpan('tcp', 'flags')).toMatchObject({ bitOffset: 272 + 104, bitLength: 8 });
  });

  it('既知の Ethernet II + ARP Request フレームとバイト単位で完全一致する（RFC 826）', () => {
    const layers: Layer[] = [
      { ...createDefaultEthernet(), dstMac: 'ff:ff:ff:ff:ff:ff' },
      createDefaultARP(),
    ];

    const result = buildPacket(layers, new Uint8Array(0));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B): broadcast dst, src, EtherType 0x0806 (ARP)
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x06,
      // ARP (28B): HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=1
      0x00, 0x01, 0x08, 0x00,
      0x06, 0x04, 0x00, 0x01,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0xc0, 0xa8, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xc0, 0xa8, 0x00, 0x02,
    ]);

    expect(result.bytes).toEqual(expected);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('matches known Ethernet II + IPv4 + TCP(179) + BGP-4 OPEN packet byte-for-byte (RFC 4271)', () => {
    const layers: Layer[] = [
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
    ];

    const result = buildPacket(layers, new Uint8Array(0));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
      // IPv4 (20B): TotalLen=69(0x0045), Proto=6(TCP), Checksum=0xa72b
      0x45, 0x00, 0x00, 0x45,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x06, 0xa7, 0x2b,
      0xc0, 0xa8, 0x00, 0x01,
      0xc0, 0xa8, 0x00, 0x02,
      // TCP (20B): 54321 -> 179, Seq=1000, Ack=1, DataOffset=5, PSH+ACK(0x18), Win=65535, Checksum=0x9525
      0xd4, 0x31, 0x00, 0xb3,
      0x00, 0x00, 0x03, 0xe8,
      0x00, 0x00, 0x00, 0x01,
      0x50, 0x18, 0xff, 0xff,
      0x95, 0x25, 0x00, 0x00,
      // BGP-4 OPEN (29B): Marker(16x 0xff), Len=29(0x001d), Type=1, Ver=4, AS=65001, Hold=180, ID=192.168.0.1, OptLen=0
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x1d, 0x01,
      0x04, 0xfd, 0xe9, 0x00, 0xb4,
      0xc0, 0xa8, 0x00, 0x01, 0x00,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('matches known Ethernet II + IPv4 + TCP(179) + BGP-4 KEEPALIVE, NOTIFICATION, and UPDATE packets byte-for-byte (RFC 4271)', () => {
    const bgpTcp = {
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
    };
    const ethBytes = [
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
    ];
    const markerBytes = new Array<number>(16).fill(0xff);

    // 1) KEEPALIVE (19B BGP -> 73B frame, IPv4 TotalLen=59 / 0x003b, IPv4 csum=0xa735, TCP csum=0x5185)
    const keepaliveRes = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        bgpTcp,
        { ...createDefaultBGP(), bgpType: 4 },
      ],
      new Uint8Array(0),
    );
    expect(keepaliveRes.ok).toBe(true);
    if (keepaliveRes.ok) {
      const expectedKeepalive = new Uint8Array([
        ...ethBytes,
        // IPv4 (20B)
        0x45, 0x00, 0x00, 0x3b,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0xa7, 0x35,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
        // TCP (20B)
        0xd4, 0x31, 0x00, 0xb3,
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0xff, 0xff,
        0x51, 0x85, 0x00, 0x00,
        // BGP KEEPALIVE (19B): Marker(16x 0xff), Length=19(0x0013), Type=4
        ...markerBytes,
        0x00, 0x13, 0x04,
      ]);
      expect(keepaliveRes.bytes).toEqual(expectedKeepalive);
      expect(keepaliveRes.warnings).toHaveLength(0);
      expectExactBitCoverage(keepaliveRes.spans, expectedKeepalive.length);
    }

    // 2) NOTIFICATION (21B BGP -> 75B frame, IPv4 TotalLen=61 / 0x003d, IPv4 csum=0xa733, TCP csum=0x4e7b)
    const notifRes = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        bgpTcp,
        { ...createDefaultBGP(), bgpType: 3, errorCode: 6, errorSubcode: 4 },
      ],
      new Uint8Array(0),
    );
    expect(notifRes.ok).toBe(true);
    if (notifRes.ok) {
      const expectedNotif = new Uint8Array([
        ...ethBytes,
        // IPv4 (20B)
        0x45, 0x00, 0x00, 0x3d,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0xa7, 0x33,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
        // TCP (20B)
        0xd4, 0x31, 0x00, 0xb3,
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0xff, 0xff,
        0x4e, 0x7b, 0x00, 0x00,
        // BGP NOTIFICATION (21B): Marker(16x 0xff), Length=21(0x0015), Type=3, Code=6, Subcode=4
        ...markerBytes,
        0x00, 0x15, 0x03, 0x06, 0x04,
      ]);
      expect(notifRes.bytes).toEqual(expectedNotif);
      expect(notifRes.warnings).toHaveLength(0);
      expectExactBitCoverage(notifRes.spans, expectedNotif.length);
    }

    // 3) UPDATE End-of-RIB (23B BGP -> 77B frame, IPv4 TotalLen=63 / 0x003f, IPv4 csum=0xa731, TCP csum=0x537d)
    const updateRes = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        bgpTcp,
        { ...createDefaultBGP(), bgpType: 2 },
      ],
      new Uint8Array(0),
    );
    expect(updateRes.ok).toBe(true);
    if (updateRes.ok) {
      const expectedUpdate = new Uint8Array([
        ...ethBytes,
        // IPv4 (20B)
        0x45, 0x00, 0x00, 0x3f,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0xa7, 0x31,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
        // TCP (20B)
        0xd4, 0x31, 0x00, 0xb3,
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0xff, 0xff,
        0x53, 0x7d, 0x00, 0x00,
        // BGP UPDATE (23B): Marker(16x 0xff), Length=23(0x0017), Type=2, WithdrawnLen=0, PathAttrLen=0
        ...markerBytes,
        0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
      ]);
      expect(updateRes.bytes).toEqual(expectedUpdate);
      expect(updateRes.warnings).toHaveLength(0);
      expectExactBitCoverage(updateRes.spans, expectedUpdate.length);
    }
  });

  it('matches known Ethernet II + Outer IPv4 (Protocol=4) + Inner IPv4 + UDP + "Hello" packet byte-for-byte (RFC 2003 IP-in-IP)', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
      createDefaultIPv4(), // Inner: 192.168.0.1 -> 192.168.0.2
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
    ];

    const result = buildPacket(layers, encodeUtf8('Hello'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
      // Outer IPv4 (20B): TotalLen=53(0x0035), Proto=4(IP-in-IP), Checksum=0x148f, 10.0.0.1 -> 10.0.0.2
      0x45, 0x00, 0x00, 0x35,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x04, 0x14, 0x8f,
      0x0a, 0x00, 0x00, 0x01,
      0x0a, 0x00, 0x00, 0x02,
      // Inner IPv4 (20B): TotalLen=33(0x0021), Proto=17(UDP), Checksum=0xa744, 192.168.0.1 -> 192.168.0.2
      0x45, 0x00, 0x00, 0x21,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x11, 0xa7, 0x44,
      0xc0, 0xa8, 0x00, 0x01,
      0xc0, 0xa8, 0x00, 0x02,
      // UDP (8B): 12345 -> 80, Len=13(0x000d), Checksum=0x2a25 (computed with INNER IPv4 pseudo-header)
      0x30, 0x39, 0x00, 0x50,
      0x00, 0x0d, 0x2a, 0x25,
      // Payload ("Hello")
      0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('allows arbitrary header stacking orders for tunneling, ICMP error quoting, and experimental packets', () => {
    // 1) L2-over-UDP encapsulation: Ethernet -> Outer IPv4 -> UDP -> Inner Ethernet -> Inner IPv4 -> TCP
    const l2OverUdp = buildPacket(
      [
        createDefaultEthernet(),
        { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
        createDefaultUDP(),
        createDefaultEthernet(),
        createDefaultIPv4(),
        createDefaultTCP(),
      ],
      new Uint8Array(0),
    );
    expect(l2OverUdp.ok).toBe(true);
    if (l2OverUdp.ok) {
      // 14 + 20 + 8 + 14 + 20 + 20 = 96 bytes
      expect(l2OverUdp.bytes.length).toBe(96);
      expectExactBitCoverage(l2OverUdp.spans, l2OverUdp.bytes.length);
    }

    // 2) RFC 792 ICMP Error quoting an original IPv4 + UDP packet (zero warnings, >= 60B)
    const icmpQuoted = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        { ...createDefaultICMP(), icmpType: 11, code: 0 }, // Time Exceeded
        createDefaultIPv4(),
        createDefaultUDP(),
      ],
      new Uint8Array(0),
    );
    expect(icmpQuoted.ok).toBe(true);
    if (icmpQuoted.ok) {
      // 14 + 20 + 8 + 20 + 8 = 70 bytes
      expect(icmpQuoted.bytes.length).toBe(70);
      expect(icmpQuoted.warnings).toHaveLength(0);
      expectExactBitCoverage(icmpQuoted.spans, icmpQuoted.bytes.length);
    }

    // 3) Arbitrary / non-standard orders all encode cleanly with exact bit coverage
    const arbitraryStacks: Layer[][] = [
      [createDefaultUDP(), createDefaultIPv4()],
      [createDefaultEthernet(), createDefaultUDP()],
      [createDefaultTCP(), createDefaultUDP()],
      [createDefaultEthernet(), createDefaultEthernet()],
      [createDefaultICMP(), createDefaultTCP()],
      [createDefaultIPv4(), createDefaultARP()],
      [createDefaultARP(), createDefaultIPv4()],
      [createDefaultARP(), createDefaultUDP()],
      [createDefaultARP(), createDefaultARP()],
      [createDefaultUDP(), createDefaultBGP()],
      [createDefaultIPv4(), createDefaultBGP()],
      [createDefaultEthernet(), createDefaultBGP()],
      [createDefaultARP(), createDefaultBGP()],
      [createDefaultICMP(), createDefaultBGP()],
      [createDefaultBGP(), createDefaultIPv4()],
      [createDefaultBGP(), createDefaultTCP()],
      [createDefaultBGP(), createDefaultBGP()],
    ];
    for (const layers of arbitraryStacks) {
      const result = buildPacket(layers, new Uint8Array(0));
      expect(result.ok).toBe(true);
      if (result.ok) {
        expectExactBitCoverage(result.spans, result.bytes.length);
      }
    }

    // Non-TCP-backed BGP (e.g., ICMP -> BGP) emits a non-blocking RFC 4271 missing-TCP warning
    const icmpBgp = buildPacket([createDefaultICMP(), createDefaultBGP()], new Uint8Array(0));
    expect(icmpBgp.ok).toBe(true);
    if (icmpBgp.ok) {
      expect(
        icmpBgp.warnings.some(
          (w) => w.layerIndex === 1 && w.message.includes('No underlying TCP layer'),
        ),
      ).toBe(true);
    }
  });

  it('scopes UDP/TCP IPv4 pseudo-header and BGP TCP context strictly to the immediately preceding layer', () => {
    // Outer IPv4 -> UDP -> Inner Ethernet -> Inner UDP (no inner IPv4 directly before inner UDP)
    const result = buildPacket(
      [
        createDefaultIPv4(),
        createDefaultUDP(),
        createDefaultEthernet(),
        createDefaultUDP(),
      ],
      encodeUtf8('ok'),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // Inner UDP (index 3) must NOT inherit outer IPv4 (index 0): checksum defaults to 0x0000 with warning
    expect(result.resolvedAutoValues[3].checksum).toBe(0);
    expect(
      result.warnings.some(
        (w) => w.layerIndex === 3 && w.fieldId === 'checksum' && w.message.includes('No underlying IPv4'),
      ),
    ).toBe(true);

    // Non-adjacent TCP (port 80) -> Ethernet -> BGP must NOT inherit outer TCP ports (warns absent TCP, not ports 1000->80)
    const bgpNonAdj = buildPacket(
      [
        { ...createDefaultTCP(), srcPort: 1000, dstPort: 80 },
        createDefaultEthernet(),
        createDefaultBGP(),
      ],
      new Uint8Array(0),
    );
    expect(bgpNonAdj.ok).toBe(true);
    if (bgpNonAdj.ok) {
      expect(
        bgpNonAdj.warnings.some(
          (w) => w.layerIndex === 2 && w.message.includes('No underlying TCP layer'),
        ),
      ).toBe(true);
      expect(
        bgpNonAdj.warnings.some(
          (w) => w.layerIndex === 2 && w.message.includes('Underlying TCP ports'),
        ),
      ).toBe(false);
    }
  });

  it('IPv4 + UDP のペイロード長境界（65507B は成功、65508B は IPv4 全長超過でエラー）', () => {
    const layers: Layer[] = [createDefaultIPv4(), createDefaultUDP()];

    // 20(IPv4) + 8(UDP) + 65507 = 65535 -> OK
    const maxOk = buildPacket(layers, new Uint8Array(65507));
    expect(maxOk.ok).toBe(true);

    // 20(IPv4) + 8(UDP) + 65508 = 65536 -> エラー
    const overflow = buildPacket(layers, new Uint8Array(65508));
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.layerIndex === 0 && e.fieldId === 'totalLength')).toBe(
        true,
      );
    }
  });

  it('複数レイヤーの入力エラーをまとめて返し、IPv4 アドレス不正時は L4 から不要な不在警告を出さない', () => {
    const layers: Layer[] = [
      { ...createDefaultEthernet(), dstMac: 'bad-mac' },
      { ...createDefaultIPv4(), srcIp: '999.1.1.1' },
      { ...createDefaultUDP(), srcPort: 70000 },
    ];

    const result = buildPacket(layers, new Uint8Array(0));
    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.errors.map((e) => `${e.layerIndex}:${e.fieldId}`)).toEqual([
      '0:dstMac',
      '1:srcIp',
      '2:srcPort',
    ]);
    expect(result.warnings.some((w) => w.message.includes('No underlying IPv4 layer'))).toBe(
      false,
    );
  });

  it('matches known Ethernet II + IPv6 + UDP + "Hello" packet byte-for-byte (RFC 8200)', () => {
    // Hand-verified UDP/IPv6 checksum (RFC 8200 §8.1):
    //   src = 2001:db8::1 -> 0x2001 + 0x0db8 + 0x0001 = 0x2dba
    //   dst = 2001:db8::2 -> 0x2001 + 0x0db8 + 0x0002 = 0x2dbb
    //   upper-layer length = 13 (0x000d), next header = 17 (0x0011)
    //   pseudo-header sum = 0x2dba + 0x2dbb + 0x000d + 0x0011 = 0x5b93
    //   UDP header (12345->80, len=13, csum=0): 0x3039 + 0x0050 + 0x000d = 0x3096
    //   payload "Hello" padded: 0x4865 + 0x6c6c + 0x6f00 = 0x123d1
    //   total = 0x1affa -> fold: 0xaffa + 1 = 0xaffb -> ~0xaffb = 0x5004
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv6(),
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
    ];

    const result = buildPacket(layers, encodeUtf8('Hello'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B): EtherType = 0x86dd (IPv6)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x86, 0xdd,
      // IPv6 (40B): Ver=6, TC=0, Flow=0, PayloadLen=13(0x000d), NH=17(0x11), HopLimit=64(0x40)
      0x60, 0x00, 0x00, 0x00,
      0x00, 0x0d, 0x11, 0x40,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
      // UDP (8B): 12345 -> 80, Len=13(0x000d), Checksum=0x5004
      0x30, 0x39, 0x00, 0x50,
      0x00, 0x0d, 0x50, 0x04,
      // Payload ("Hello")
      0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('matches known Ethernet II + IPv6 + TCP SYN packet byte-for-byte (RFC 8200 / RFC 9293)', () => {
    // Hand-verified TCP/IPv6 checksum (RFC 8200 §8.1):
    //   pseudo: 0x2dba + 0x2dbb + 0x0014 (20B) + 0x0006 (TCP) = 0x5b8f
    //   TCP SYN (54321->443, seq=1000, ack=0, off=5, SYN, win=65535):
    //   0xd431 + 0x01bb + 0x03e8 + 0x5002 + 0xffff = 0x229d5
    //   total = 0x28564 -> fold: 0x8564 + 2 = 0x8566 -> ~0x8566 = 0x7a99
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv6(),
      createDefaultTCP(),
    ];

    const result = buildPacket(layers, new Uint8Array(0));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x86, 0xdd,
      // IPv6 (40B): PayloadLen=20(0x0014), NH=6(0x06), HopLimit=64
      0x60, 0x00, 0x00, 0x00,
      0x00, 0x14, 0x06, 0x40,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
      // TCP (20B): 54321 -> 443, Seq=1000, Ack=0, DataOffset=5, SYN, Win=65535, Checksum=0x7a99
      0xd4, 0x31, 0x01, 0xbb,
      0x00, 0x00, 0x03, 0xe8,
      0x00, 0x00, 0x00, 0x00,
      0x50, 0x02, 0xff, 0xff,
      0x7a, 0x99, 0x00, 0x00,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('matches known 6in4 tunnel (Ethernet + IPv4 Proto 41 + IPv6 + UDP + "Hello") and uses inner IPv6 pseudo-header', () => {
    // Outer IPv4 (10.0.0.1 -> 10.0.0.2, TotalLen=73=0x0049, ID=0x1234, DF=0x4000, TTL=64, Proto=41=0x29):
    //   sum = 0x4500 + 0x0049 + 0x1234 + 0x4000 + 0x4029 + 0x0a00 + 0x0001 + 0x0a00 + 0x0002 = 0xeba9
    //   ~0xeba9 = 0x1456
    // UDP checksum MUST use inner IPv6 (2001:db8::1 -> 2001:db8::2) = 0x5004 (not outer IPv4).
    const layers: Layer[] = [
      createDefaultEthernet(),
      { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
      createDefaultIPv6(),
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
    ];

    const result = buildPacket(layers, encodeUtf8('Hello'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B): EtherType = 0x0800 (IPv4)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x08, 0x00,
      // Outer IPv4 (20B): TotalLen=73(0x0049), Proto=41(0x29), Checksum=0x1456
      0x45, 0x00, 0x00, 0x49,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x29, 0x14, 0x56,
      0x0a, 0x00, 0x00, 0x01,
      0x0a, 0x00, 0x00, 0x02,
      // Inner IPv6 (40B): PayloadLen=13(0x000d), NH=17(0x11), HopLimit=64
      0x60, 0x00, 0x00, 0x00,
      0x00, 0x0d, 0x11, 0x40,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
      // UDP (8B): checksum 0x5004 from inner IPv6
      0x30, 0x39, 0x00, 0x50,
      0x00, 0x0d, 0x50, 0x04,
      // Payload ("Hello")
      0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('matches known 4in6 tunnel (Ethernet + IPv6 NH 4 + IPv4 + UDP + "Hello") and uses inner IPv4 pseudo-header', () => {
    // Outer IPv6 (2001:db8::1 -> 2001:db8::2, PayloadLen=33=0x0021, NH=4=IPv4, HopLimit=64)
    // Inner IPv4 (192.168.0.1 -> 192.168.0.2, TotalLen=33=0x0021, Proto=17, Checksum=0xa744)
    // UDP checksum MUST use inner IPv4 (192.168.0.1 -> 192.168.0.2) = 0x2a25 (not outer IPv6).
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv6(),
      createDefaultIPv4(),
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
    ];

    const result = buildPacket(layers, encodeUtf8('Hello'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B): EtherType = 0x86dd (IPv6)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x86, 0xdd,
      // Outer IPv6 (40B): PayloadLen=33(0x0021), NH=4(0x04), HopLimit=64
      0x60, 0x00, 0x00, 0x00,
      0x00, 0x21, 0x04, 0x40,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
      // Inner IPv4 (20B): TotalLen=33(0x0021), Proto=17(0x11), Checksum=0xa744
      0x45, 0x00, 0x00, 0x21,
      0x12, 0x34, 0x40, 0x00,
      0x40, 0x11, 0xa7, 0x44,
      0xc0, 0xa8, 0x00, 0x01,
      0xc0, 0xa8, 0x00, 0x02,
      // UDP (8B): checksum 0x2a25 from inner IPv4
      0x30, 0x39, 0x00, 0x50,
      0x00, 0x0d, 0x2a, 0x25,
      // Payload ("Hello")
      0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);
  });

  it('validates IPv6 Payload Length boundary (65535B succeeds; 65536B fails)', () => {
    const layers: Layer[] = [createDefaultIPv6()];

    const maxOk = buildPacket(layers, new Uint8Array(65535));
    expect(maxOk.ok).toBe(true);

    const overflow = buildPacket(layers, new Uint8Array(65536));
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(
        overflow.errors.some((e) => e.layerIndex === 0 && e.fieldId === 'payloadLength'),
      ).toBe(true);
    }
  });

  it('matches known Ethernet II + IPv6 + ICMPv6 Echo Request + "ping" packet byte-for-byte (RFC 4443)', () => {
    // Hand-verified ICMPv6 checksum (RFC 4443 §2.3 / RFC 8200 §8.1):
    //   pseudo: 2001:db8::1 (0x2dba) + 2001:db8::2 (0x2dbb) + len=12 (0x000c) + NH=58 (0x003a) = 0x5bbb
    //   ICMPv6: Type=128/Code=0 (0x8000) + ID=1 (0x0001) + Seq=1 (0x0001) + "ping" (0x7069+0x6e67=0xded0) = 0x15ed2
    //   total = 0x1ba8d -> fold: 0xba8d + 1 = 0xba8e -> ~0xba8e = 0x4571
    const baseLayers: Layer[] = [
      createDefaultEthernet(),
      createDefaultIPv6(),
      createDefaultICMPv6(),
    ];

    const result = buildPacket(baseLayers, encodeUtf8('ping'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const expected = new Uint8Array([
      // Ethernet II (14B): EtherType = 0x86dd (IPv6)
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x86, 0xdd,
      // IPv6 (40B): PayloadLen=12(0x000c), NH=58(0x3a), HopLimit=64
      0x60, 0x00, 0x00, 0x00,
      0x00, 0x0c, 0x3a, 0x40,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
      // ICMPv6 Echo Request (8B): Type=128, Code=0, Checksum=0x4571, ID=1, Seq=1
      0x80, 0x00, 0x45, 0x71,
      0x00, 0x01, 0x00, 0x01,
      // Payload ("ping")
      0x70, 0x69, 0x6e, 0x67,
    ]);

    expect(result.bytes).toEqual(expected);
    expect(result.warnings).toHaveLength(0);
    expectExactBitCoverage(result.spans, expected.length);

    // Changing ONLY the IPv6 source address MUST change the ICMPv6 checksum (proves pseudo-header inclusion)
    const changedSrc = buildPacket(
      [
        createDefaultEthernet(),
        { ...createDefaultIPv6(), srcIp: '2001:db8::9' },
        createDefaultICMPv6(),
      ],
      encodeUtf8('ping'),
    );
    expect(changedSrc.ok).toBe(true);
    if (!changedSrc.ok) return;
    // 0x4571 - 8 = 0x4569
    expect(changedSrc.bytes.slice(56, 58)).toEqual(new Uint8Array([0x45, 0x69]));
    expect(changedSrc.bytes.slice(56, 58)).not.toEqual(result.bytes.slice(56, 58));
  });
});
