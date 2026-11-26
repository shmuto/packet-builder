import { describe, expect, it } from 'vitest';
import { internetChecksum } from '../checksum';
import { decodeIPv4OptionTypeByte, encodeIPv4 } from './ipv4';
import { autoValue, manualValue, type IPv4Layer } from './types';

function makeBaseIPv4(overrides: Partial<IPv4Layer> = {}): IPv4Layer {
  return {
    type: 'ipv4',
    ihl: autoValue(),
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
    options: [],
    ...overrides,
  };
}

describe('encodeIPv4', () => {
  it('IHL=5 固定の 20 バイト IPv4 ヘッダを組み立て、チェックサム再計算が 0 になる', () => {
    const result = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 13,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(
      new Uint8Array([
        0x45, 0x00, 0x00, 0x21,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x11, 0xa7, 0x44,
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02,
      ]),
    );
    expect(internetChecksum(result.bytes)).toBe(0);
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({
      ihl: 5,
      totalLength: 33,
      protocol: 17,
      headerChecksum: 0xa744,
    });
  });

  it('Router Alert オプション付き IPv4 ヘッダ（IHL=6、94 04 00 00）の既知バイト列とチェックサムを独立検算付きで検証する', () => {
    // Independent RFC 1071 / RFC 791 header checksum verification:
    // Words (16-bit big-endian, checksum = 0):
    //   w0: Version=4, IHL=6, TOS=0x00    -> 0x4600
    //   w1: Total Length=24 (24 + 0)      -> 0x0018
    //   w2: Identification=0x1234         -> 0x1234
    //   w3: Flags=DF, FragOffset=0        -> 0x4000
    //   w4: TTL=1, Protocol=2 (IGMP)      -> 0x0102
    //   w5: Header Checksum (zeroed)      -> 0x0000
    //   w6: Src IP hi (192.168)           -> 0xc0a8
    //   w7: Src IP lo (0.1)               -> 0x0001
    //   w8: Dst IP hi (224.0)             -> 0xe000
    //   w9: Dst IP lo (0.1)               -> 0x0001
    //   w10: Router Alert Type=0x94,Len=4 -> 0x9404
    //   w11: Router Alert Value=0x0000    -> 0x0000
    // Sum:
    //   0x4600 + 0x0018 = 0x4618
    //   + 0x1234 = 0x584c
    //   + 0x4000 = 0x984c
    //   + 0x0102 = 0x994e
    //   + 0xc0a8 = 0x159f6
    //   + 0x0001 = 0x159f7
    //   + 0xe000 = 0x239f7
    //   + 0x0001 = 0x239f8
    //   + 0x9404 = 0x2cdfc
    // Fold carry: 0xcdfc + 0x0002 = 0xcdfe
    // One's complement: ~0xcdfe & 0xffff = 0x3201
    const result = encodeIPv4(
      makeBaseIPv4({
        ttl: 1,
        protocol: manualValue(2),
        dstIp: '224.0.0.1',
        options: [{ kind: 'routerAlert', value: 0 }],
      }),
      {
        layerIndex: 0,
        upperLayerType: null,
        upperBytesLength: 0,
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.length).toBe(24);
    expect(result.bytes[0]).toBe(0x46);
    expect(result.bytes.slice(2, 4)).toEqual(new Uint8Array([0x00, 0x18]));
    expect(result.bytes.slice(10, 12)).toEqual(new Uint8Array([0x32, 0x01]));
    expect(result.bytes.slice(20, 24)).toEqual(new Uint8Array([0x94, 0x04, 0x00, 0x00]));
    expect(internetChecksum(result.bytes)).toBe(0);
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({
      ihl: 6,
      totalLength: 24,
      protocol: 0,
      headerChecksum: 0x3201,
    });
  });

  it('RFC 791 §3.1 に従うオプション Type バイト分解（copied / class / number）が各種別と一致する', () => {
    expect(decodeIPv4OptionTypeByte(0)).toEqual({ copied: 0, optionClass: 0, number: 0 }); // EOL
    expect(decodeIPv4OptionTypeByte(1)).toEqual({ copied: 0, optionClass: 0, number: 1 }); // NOP
    expect(decodeIPv4OptionTypeByte(7)).toEqual({ copied: 0, optionClass: 0, number: 7 }); // RR
    expect(decodeIPv4OptionTypeByte(68)).toEqual({ copied: 0, optionClass: 2, number: 4 }); // Timestamp
    expect(decodeIPv4OptionTypeByte(131)).toEqual({ copied: 1, optionClass: 0, number: 3 }); // LSRR
    expect(decodeIPv4OptionTypeByte(137)).toEqual({ copied: 1, optionClass: 0, number: 9 }); // SSRR
    expect(decodeIPv4OptionTypeByte(148)).toEqual({ copied: 1, optionClass: 0, number: 20 }); // Router Alert
  });

  it('パディング境界（1/3/4/5/40 バイトで IHL 6/6/6/7/15、41 バイトはエラー）と連続 FieldSpan を検証する', () => {
    const cases: readonly {
      name: string;
      options: IPv4Layer['options'];
      expectedIhl: number;
      expectPadSpan: boolean;
    }[] = [
      { name: '1 byte (NOP)', options: [{ kind: 'nop' }], expectedIhl: 6, expectPadSpan: true },
      {
        name: '3 bytes (RR with 0 addrs)',
        options: [{ kind: 'rr', pointer: autoValue(), addresses: [] }],
        expectedIhl: 6,
        expectPadSpan: true,
      },
      {
        name: '4 bytes (Router Alert)',
        options: [{ kind: 'routerAlert', value: 0 }],
        expectedIhl: 6,
        expectPadSpan: false,
      },
      {
        name: '5 bytes (Router Alert + NOP)',
        options: [{ kind: 'routerAlert', value: 0 }, { kind: 'nop' }],
        expectedIhl: 7,
        expectPadSpan: true,
      },
      {
        name: '40 bytes (10 x Router Alert)',
        options: Array.from({ length: 10 }, () => ({ kind: 'routerAlert' as const, value: 0 })),
        expectedIhl: 15,
        expectPadSpan: false,
      },
    ];

    for (const c of cases) {
      const res = encodeIPv4(makeBaseIPv4({ options: c.options }), {
        layerIndex: 0,
        upperLayerType: 'udp',
        upperBytesLength: 8,
      });
      expect(res.ok, c.name).toBe(true);
      if (!res.ok) continue;
      expect(res.bytes[0] & 0x0f, c.name).toBe(c.expectedIhl);
      expect(res.bytes.length, c.name).toBe(c.expectedIhl * 4);
      expect(res.resolvedAutoValues.ihl, c.name).toBe(c.expectedIhl);
      expect(res.resolvedAutoValues.totalLength, c.name).toBe(c.expectedIhl * 4 + 8);
      expect(internetChecksum(res.bytes), c.name).toBe(0);
      expect(res.spans.some((s) => s.fieldId === 'optionsPadding'), c.name).toBe(c.expectPadSpan);

      // Strictly contiguous bit spans with no gaps
      let cursor = 0;
      for (const span of res.spans) {
        expect(span.bitOffset, `${c.name} ${span.fieldId}`).toBe(cursor);
        cursor += span.bitLength;
      }
      expect(cursor, c.name).toBe(res.bytes.length * 8);
    }

    // 41 bytes -> error
    const overflow = encodeIPv4(
      makeBaseIPv4({
        options: [
          ...Array.from({ length: 10 }, () => ({ kind: 'routerAlert' as const, value: 0 })),
          { kind: 'nop' },
        ],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.fieldId === 'options' && e.message.includes('40'))).toBe(true);
    }
  });

  it('IPv4 オプションの学習用警告（LSRR/SSRR・不正ポインタ・Router Alert != 0・EOL 後バイト）をすべて検証する', () => {
    // 1) LSRR warning (RFC 7126 §4.3)
    const lsrr = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'lsrr', pointer: autoValue(), addresses: ['192.0.2.1'] }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(lsrr.ok).toBe(true);
    if (lsrr.ok) {
      expect(lsrr.warnings.some((w) => w.message.includes('RFC 7126 §4.3'))).toBe(true);
    }

    // 2) SSRR warning (RFC 7126 §4.4)
    const ssrr = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'ssrr', pointer: autoValue(), addresses: ['192.0.2.1'] }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(ssrr.ok).toBe(true);
    if (ssrr.ok) {
      expect(ssrr.warnings.some((w) => w.message.includes('RFC 7126 §4.4'))).toBe(true);
    }

    // 3) RR pointer < 4 or not 4 + 4k
    const ptrTooSmall = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'rr', pointer: manualValue(3), addresses: ['0.0.0.0'] }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(ptrTooSmall.ok).toBe(true);
    if (ptrTooSmall.ok) {
      expect(ptrTooSmall.warnings.some((w) => w.fieldId === 'options[0].rr.pointer')).toBe(true);
    }

    const ptrMisaligned = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'rr', pointer: manualValue(6), addresses: ['0.0.0.0'] }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(ptrMisaligned.ok).toBe(true);
    if (ptrMisaligned.ok) {
      expect(ptrMisaligned.warnings.some((w) => w.fieldId === 'options[0].rr.pointer')).toBe(true);
    }

    const ptrValid8 = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'rr', pointer: manualValue(8), addresses: ['192.0.2.1', '0.0.0.0'] }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(ptrValid8.ok && ptrValid8.warnings.length === 0).toBe(true);

    // 4) Router Alert value != 0 (RFC 2113 §2.1)
    const raNonZero = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'routerAlert', value: 1 }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(raNonZero.ok).toBe(true);
    if (raNonZero.ok) {
      expect(raNonZero.warnings.some((w) => w.message.includes('RFC 2113 §2.1'))).toBe(true);
    }

    // 5) Bytes after End of Option List (typed EOL and Raw Type 0)
    const afterEol = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'eol' }, { kind: 'nop' }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(afterEol.ok).toBe(true);
    if (afterEol.ok) {
      expect(afterEol.warnings.some((w) => w.message.includes('End of Option List'))).toBe(true);
    }

    const afterRawEol = encodeIPv4(
      makeBaseIPv4({
        options: [
          { kind: 'raw', optionType: 0, length: { mode: 'none' }, dataHex: '' },
          { kind: 'nop' },
        ],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(afterRawEol.ok).toBe(true);
    if (afterRawEol.ok) {
      expect(afterRawEol.warnings.some((w) => w.message.includes('End of Option List'))).toBe(true);
    }

    // 6) Raw Type 0 / Type 1 with TLV Length field -> 1-byte option warning
    const rawNopWithLen = encodeIPv4(
      makeBaseIPv4({
        options: [{ kind: 'raw', optionType: 1, length: autoValue(), dataHex: '' }],
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );
    expect(rawNopWithLen.ok).toBe(true);
    if (rawNopWithLen.ok) {
      expect(
        rawNopWithLen.warnings.some(
          (w) => w.fieldId === 'options[0].raw.length' && w.message.includes('1-byte option'),
        ),
      ).toBe(true);
    }
  });

  it('上位レイヤー種別に応じて Protocol 番号を自動設定する（ICMP=1, IP-in-IP=4, TCP=6, UDP=17, IPv6=41）', () => {
    const icmp = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'icmp',
      upperBytesLength: 8,
    });
    const ipip = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'ipv4',
      upperBytesLength: 20,
    });
    const tcp = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'tcp',
      upperBytesLength: 20,
    });
    const udp = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 8,
    });
    const ipv6 = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'ipv6',
      upperBytesLength: 40,
    });

    expect(icmp.ok && icmp.bytes[9]).toBe(1);
    expect(ipip.ok && ipip.bytes[9]).toBe(4);
    expect(ipip.ok && ipip.warnings).toEqual([]);
    expect(tcp.ok && tcp.bytes[9]).toBe(6);
    expect(udp.ok && udp.bytes[9]).toBe(17);
    expect(ipv6.ok && ipv6.bytes[9]).toBe(41);
    expect(ipv6.ok && ipv6.warnings).toEqual([]);
  });

  it('Flags(3bit) と Fragment Offset(13bit) の境界ビットを正しく配置する', () => {
    const result = encodeIPv4(
      makeBaseIPv4({
        flags: { reserved: true, df: false, mf: true },
        fragmentOffset: 0x1fff,
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // R=1(0b100) | DF=0 | MF=1(0b001) = 0b101 -> 0b101_1111111111111 = 0xbfff
    expect(result.bytes.slice(6, 8)).toEqual(new Uint8Array([0xbf, 0xff]));
    expect(result.warnings.some((w) => w.fieldId === 'flags')).toBe(true);
  });

  it('手動指定値が自動計算値より優先され、警告を返す', () => {
    const result = encodeIPv4(
      makeBaseIPv4({
        ihl: manualValue(6),
        totalLength: manualValue(100),
        protocol: manualValue(99),
        headerChecksum: manualValue(0xbeef),
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes[0]).toBe(0x46);
    expect(result.bytes.slice(2, 4)).toEqual(new Uint8Array([0x00, 100]));
    expect(result.bytes[9]).toBe(99);
    expect(result.bytes.slice(10, 12)).toEqual(new Uint8Array([0xbe, 0xef]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual([
      'ihl',
      'totalLength',
      'protocol',
      'headerChecksum',
    ]);
  });

  it('全長 65535 バイトは成功し、65536 バイトはエラーになる（RFC 791）', () => {
    const okMax = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 65515, // 20 + 65515 = 65535
    });
    expect(okMax.ok).toBe(true);

    const overflow = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 65516, // 20 + 65516 = 65536
    });
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.fieldId === 'totalLength')).toBe(true);
    }
  });

  it('範囲外のフィールドや不正な IPv4 アドレスをすべてエラーとして返す', () => {
    const result = encodeIPv4(
      makeBaseIPv4({
        tos: 256,
        identification: -1,
        fragmentOffset: 8192,
        ttl: 300,
        srcIp: '999.0.0.1',
        dstIp: '1.2.3',
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'tos',
      'identification',
      'fragmentOffset',
      'ttl',
      'srcIp',
      'dstIp',
    ]);
  });
});
