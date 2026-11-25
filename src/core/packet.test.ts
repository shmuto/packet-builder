import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from './bytes';
import { autoValue, type FieldSpan, type Layer } from './layers/types';
import { buildPacket } from './packet';
import {
  createDefaultEthernet,
  createDefaultICMP,
  createDefaultIPv4,
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

  it('対応していないレイヤー順序はエラーを返す', () => {
    const invalidOrders: Layer[][] = [
      [createDefaultUDP(), createDefaultIPv4()],
      [createDefaultEthernet(), createDefaultUDP()],
      [createDefaultTCP(), createDefaultUDP()],
      [createDefaultIPv4(), createDefaultIPv4()],
      [createDefaultEthernet(), createDefaultEthernet()],
      [createDefaultICMP(), createDefaultTCP()],
    ];

    for (const layers of invalidOrders) {
      const result = buildPacket(layers, new Uint8Array(0));
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.errors.length).toBeGreaterThan(0);
      }
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
});
