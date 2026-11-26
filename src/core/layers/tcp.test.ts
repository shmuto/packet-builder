import { describe, expect, it } from 'vitest';
import { parseIPv6 } from '../bytes';
import { encodeTCP } from './tcp';
import { autoValue, manualValue, type TCPLayer } from './types';

function mustIPv6(addr: string): Uint8Array {
  const res = parseIPv6(addr);
  if (!res.ok) throw new Error(res.error);
  return res.value;
}

function makeBaseTCP(overrides: Partial<TCPLayer> = {}): TCPLayer {
  return {
    type: 'tcp',
    srcPort: 54321,
    dstPort: 443,
    seqNumber: 1000,
    ackNumber: 0,
    dataOffset: autoValue(),
    flags: {
      cwr: false,
      ece: false,
      urg: false,
      ack: false,
      psh: false,
      rst: false,
      syn: true,
      fin: false,
    },
    windowSize: 65535,
    checksum: autoValue(),
    urgentPointer: 0,
    options: [],
    ...overrides,
  };
}

describe('encodeTCP', () => {
  const validIPv4 = {
    status: 'valid' as const,
    version: 4 as const,
    srcIp: new Uint8Array([192, 168, 0, 1]),
    dstIp: new Uint8Array([192, 168, 0, 2]),
  };

  const validIPv6 = {
    status: 'valid' as const,
    version: 6 as const,
    srcIp: mustIPv6('2001:db8::1'),
    dstIp: mustIPv6('2001:db8::2'),
  };

  it('TCP SYN ヘッダ（20 バイト、オプションなし）と IPv4 擬似ヘッダチェックサムを正しく組み立てる', () => {
    const result = encodeTCP(makeBaseTCP(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv4,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(
      new Uint8Array([
        0xd4, 0x31, 0x01, 0xbb,
        0x00, 0x00, 0x03, 0xe8,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xff, 0xff,
        0x54, 0xba, 0x00, 0x00,
      ]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ dataOffset: 5, checksum: 0x54ba });
  });

  it('Linux SYN オプションセット（20B、Data Offset 10）の既知バイト列とチェックサムを独立検算付きで検証する', () => {
    // Independent RFC 1071 / RFC 9293 checksum calculation:
    // IPv4 pseudo-header (192.168.0.1 -> 192.168.0.2, proto 6, TCP len 40 = 0x0028):
    //   0xc0a8 + 0x0001 + 0xc0a8 + 0x0002 + 0x0006 + 0x0028 = 0x18181
    // TCP base header (20 bytes, Data Offset = 10 -> 0xa0, SYN = 0x02, checksum = 0):
    //   0xd431 + 0x01bb + 0x0000 + 0x03e8 + 0x0000 + 0x0000 + 0xa002 + 0xffff + 0x0000 + 0x0000
    //   = 0x279d5
    // TCP options (20 bytes):
    //   MSS 1460:       02 04 05 b4  -> 0x0204 + 0x05b4 = 0x07b8
    //   SACK-Permitted: 04 02        -> 0x0402
    //   Timestamps:     08 0a 00 0f 42 40 00 00 00 00
    //                   -> 0x080a + 0x000f + 0x4240 + 0x0000 + 0x0000 = 0x4a59
    //   NOP + WScale 7: 01 03 03 07  -> 0x0103 + 0x0307 = 0x040a
    //   options sum = 0x07b8 + 0x0402 + 0x4a59 + 0x040a = 0x5a1d
    // Total 32-bit sum = 0x18181 + 0x279d5 + 0x5a1d = 0x45573
    // Fold carry: 0x5573 + 0x0004 = 0x5577
    // One's complement: ~0x5577 & 0xffff = 0xaa88
    const result = encodeTCP(
      makeBaseTCP({
        options: [
          { kind: 'mss', mss: 1460 },
          { kind: 'sackPermitted' },
          { kind: 'timestamps', tsVal: 1000000, tsEcr: 0 },
          { kind: 'nop' },
          { kind: 'windowScale', shiftCount: 7 },
        ],
      }),
      {
        layerIndex: 0,
        upperBytes: new Uint8Array(0),
        ip: validIPv4,
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.length).toBe(40);
    expect(result.bytes[12]).toBe(0xa0);
    expect(result.bytes.slice(16, 18)).toEqual(new Uint8Array([0xaa, 0x88]));
    expect(result.bytes.slice(20)).toEqual(
      new Uint8Array([
        0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02,
        0x08, 0x0a, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x01,
        0x03, 0x03, 0x07,
      ]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ dataOffset: 10, checksum: 0xaa88 });
  });

  it('オプション長 1/2/3/4/5/40 バイトの 32-bit パディングと 41 バイト超過エラーを正しく扱う', () => {
    const cases: readonly {
      name: string;
      options: TCPLayer['options'];
      expectedLen: number;
      expectedDo: number;
      expectPadSpan: boolean;
    }[] = [
      { name: '1 byte (NOP)', options: [{ kind: 'nop' }], expectedLen: 24, expectedDo: 6, expectPadSpan: true },
      { name: '2 bytes (SACK-Perm)', options: [{ kind: 'sackPermitted' }], expectedLen: 24, expectedDo: 6, expectPadSpan: true },
      { name: '3 bytes (WScale)', options: [{ kind: 'windowScale', shiftCount: 7 }], expectedLen: 24, expectedDo: 6, expectPadSpan: true },
      { name: '4 bytes (MSS)', options: [{ kind: 'mss', mss: 1460 }], expectedLen: 24, expectedDo: 6, expectPadSpan: false },
      { name: '5 bytes (MSS + NOP)', options: [{ kind: 'mss', mss: 1460 }, { kind: 'nop' }], expectedLen: 28, expectedDo: 7, expectPadSpan: true },
      {
        name: '40 bytes (10 x MSS)',
        options: Array.from({ length: 10 }, () => ({ kind: 'mss' as const, mss: 1460 })),
        expectedLen: 60,
        expectedDo: 15,
        expectPadSpan: false,
      },
    ];

    for (const c of cases) {
      const res = encodeTCP(makeBaseTCP({ options: c.options }), {
        layerIndex: 0,
        upperBytes: new Uint8Array(0),
        ip: validIPv4,
      });
      expect(res.ok, c.name).toBe(true);
      if (!res.ok) continue;
      expect(res.bytes.length, c.name).toBe(c.expectedLen);
      expect(res.bytes[12] >>> 4, c.name).toBe(c.expectedDo);
      expect(res.resolvedAutoValues.dataOffset, c.name).toBe(c.expectedDo);
      expect(res.spans.some((s) => s.fieldId === 'optionsPadding'), c.name).toBe(c.expectPadSpan);

      // Spans must be strictly contiguous with no gaps up to the end of padding
      let cursor = 0;
      for (const span of res.spans) {
        expect(span.bitOffset, `${c.name} span ${span.fieldId}`).toBe(cursor);
        cursor += span.bitLength;
      }
      expect(cursor, c.name).toBe(res.bytes.length * 8);
    }

    // 41 bytes -> error
    const tooLarge = encodeTCP(
      makeBaseTCP({
        options: [
          ...Array.from({ length: 10 }, () => ({ kind: 'mss' as const, mss: 1460 })),
          { kind: 'nop' },
        ],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(tooLarge.ok).toBe(false);
    if (!tooLarge.ok) {
      expect(tooLarge.errors.some((e) => e.fieldId === 'options' && e.message.includes('40'))).toBe(true);
    }
  });

  it('チェックサムが TCP オプション内容の変化を反映する（IPv4 および IPv6）', () => {
    const mss1460 = encodeTCP(makeBaseTCP({ options: [{ kind: 'mss', mss: 1460 }] }), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv4,
    });
    const mss1200 = encodeTCP(makeBaseTCP({ options: [{ kind: 'mss', mss: 1200 }] }), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv4,
    });
    expect(mss1460.ok && mss1200.ok).toBe(true);
    if (mss1460.ok && mss1200.ok) {
      expect(mss1460.resolvedAutoValues.checksum).not.toBe(mss1200.resolvedAutoValues.checksum);
    }

    const v6WithOpt = encodeTCP(makeBaseTCP({ options: [{ kind: 'mss', mss: 1440 }] }), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv6,
    });
    const v6NoOpt = encodeTCP(makeBaseTCP(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv6,
    });
    expect(v6WithOpt.ok && v6NoOpt.ok).toBe(true);
    if (v6WithOpt.ok && v6NoOpt.ok) {
      expect(v6WithOpt.resolvedAutoValues.checksum).not.toBe(v6NoOpt.resolvedAutoValues.checksum);
    }
  });

  it('SACK 複数ブロックの連続 FieldSpan と Raw オプションのエラー・警告を検証する', () => {
    const sackRes = encodeTCP(
      makeBaseTCP({
        flags: { cwr: false, ece: false, urg: false, ack: true, psh: false, rst: false, syn: false, fin: false },
        options: [
          {
            kind: 'sack',
            blocks: [
              { left: 100, right: 200 },
              { left: 300, right: 400 },
            ],
          },
        ],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(sackRes.ok).toBe(true);
    if (sackRes.ok) {
      expect(sackRes.bytes.length).toBe(40); // 20 + (2 + 16 = 18) + 2 pad
      expect(sackRes.spans.map((s) => s.fieldId)).toContain('options[0].sack.blocks[1].left');
      expect(sackRes.spans.map((s) => s.fieldId)).toContain('options[0].sack.blocks[1].right');
      expect(sackRes.spans.map((s) => s.fieldId)).toContain('optionsPadding');
      let cursor = 0;
      for (const s of sackRes.spans) {
        expect(s.bitOffset).toBe(cursor);
        cursor += s.bitLength;
      }
      expect(cursor).toBe(40 * 8);
    }

    // Raw option with Length < 2 -> error
    const badLen = encodeTCP(
      makeBaseTCP({
        options: [{ kind: 'raw', optionKind: 30, length: manualValue(1), dataHex: '' }],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(badLen.ok).toBe(false);
    if (!badLen.ok) {
      expect(badLen.errors.some((e) => e.fieldId === 'options[0].raw.length')).toBe(true);
    }

    // Raw option with manual Length mismatching data -> warning
    const mismatchLen = encodeTCP(
      makeBaseTCP({
        options: [{ kind: 'raw', optionKind: 30, length: manualValue(8), dataHex: 'aa bb' }],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(mismatchLen.ok).toBe(true);
    if (mismatchLen.ok) {
      expect(mismatchLen.warnings.some((w) => w.fieldId === 'options[0].raw.length')).toBe(true);
    }
  });

  it('学習用警告と境界値（SYN なし・WScale 14/15・SACK 4/5 ブロック・SACK+TS 3/4 ブロック・EOL 後バイト）を検証する', () => {
    const ackFlags = {
      cwr: false,
      ece: false,
      urg: false,
      ack: true,
      psh: false,
      rst: false,
      syn: false,
      fin: false,
    };

    // MSS / Window Scale / SACK-Permitted without SYN
    for (const opt of [
      { kind: 'mss' as const, mss: 1460 },
      { kind: 'windowScale' as const, shiftCount: 7 },
      { kind: 'sackPermitted' as const },
    ]) {
      const res = encodeTCP(makeBaseTCP({ flags: ackFlags, options: [opt] }), {
        layerIndex: 0,
        upperBytes: new Uint8Array(0),
        ip: validIPv4,
      });
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.warnings.some((w) => w.message.includes('SYN'))).toBe(true);
      }
    }

    // Window Scale shift 14 (no warning) vs 15 (warning)
    const ws14 = encodeTCP(makeBaseTCP({ options: [{ kind: 'windowScale', shiftCount: 14 }] }), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv4,
    });
    expect(ws14.ok && ws14.warnings.length === 0).toBe(true);

    const ws15 = encodeTCP(makeBaseTCP({ options: [{ kind: 'windowScale', shiftCount: 15 }] }), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv4,
    });
    expect(ws15.ok).toBe(true);
    if (ws15.ok) {
      expect(ws15.warnings.some((w) => w.fieldId === 'options[0].windowScale.shiftCount')).toBe(true);
    }

    // SACK 4 blocks (fits, no warning) vs 5 blocks (warning + >40B error)
    const makeBlocks = (n: number) =>
      Array.from({ length: n }, (_, idx) => ({ left: idx * 1000, right: idx * 1000 + 500 }));

    const sack4 = encodeTCP(
      makeBaseTCP({ flags: ackFlags, options: [{ kind: 'sack', blocks: makeBlocks(4) }] }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(sack4.ok).toBe(true);
    if (sack4.ok) {
      expect(sack4.warnings).toHaveLength(0);
      expect(sack4.bytes.length).toBe(56); // 20 + 34 + 2 pad
    }

    const sack5 = encodeTCP(
      makeBaseTCP({ flags: ackFlags, options: [{ kind: 'sack', blocks: makeBlocks(5) }] }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(sack5.ok).toBe(false);
    expect(sack5.warnings.some((w) => w.message.includes('maximum 4 blocks'))).toBe(true);

    // SACK 3 blocks + Timestamps (fits, no warning) vs 4 blocks + Timestamps (warning + >40B error)
    const sack3Ts = encodeTCP(
      makeBaseTCP({
        flags: ackFlags,
        options: [
          { kind: 'timestamps', tsVal: 1, tsEcr: 2 },
          { kind: 'sack', blocks: makeBlocks(3) },
        ],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(sack3Ts.ok).toBe(true);
    if (sack3Ts.ok) {
      expect(sack3Ts.warnings).toHaveLength(0);
      expect(sack3Ts.bytes.length).toBe(56); // 20 + 10 + 26 = 56
    }

    const sack4Ts = encodeTCP(
      makeBaseTCP({
        flags: ackFlags,
        options: [
          { kind: 'timestamps', tsVal: 1, tsEcr: 2 },
          { kind: 'sack', blocks: makeBlocks(4) },
        ],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(sack4Ts.ok).toBe(false);
    expect(sack4Ts.warnings.some((w) => w.message.includes('maximum 3 blocks with Timestamps'))).toBe(true);

    // Bytes after End of Option List
    const afterEol = encodeTCP(
      makeBaseTCP({
        options: [{ kind: 'eol' }, { kind: 'nop' }],
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(afterEol.ok).toBe(true);
    if (afterEol.ok) {
      expect(afterEol.warnings.some((w) => w.message.includes('End of Option List'))).toBe(true);
    }
  });

  it('IPv6 擬似ヘッダ込みの TCP SYN チェックサムを正しく組み立てる（RFC 8200 §8.1）', () => {
    // Hand verification:
    // src=2001:db8::1 (0x2dba) + dst=2001:db8::2 (0x2dbb) + len=0x0014 + nh=0x0006 = 0x5b8f
    // TCP: 0xd431 + 0x01bb + 0x03e8 + 0x5002 + 0xffff = 0x229d5
    // total = 0x28564 -> fold: 0x8564 + 2 = 0x8566 -> ~0x8566 = 0x7a99
    const result = encodeTCP(makeBaseTCP(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: validIPv6,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(16, 18)).toEqual(new Uint8Array([0x7a, 0x99]));
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ dataOffset: 5, checksum: 0x7a99 });
  });

  it('チェックサム計算結果が 0x0000 になる場合、IPv4/IPv6 ともに 0x0000 のまま格納する', () => {
    const zeroTcp = makeBaseTCP({
      srcPort: 0xafe5,
      dstPort: 0,
      seqNumber: 0,
      ackNumber: 0,
      flags: {
        cwr: false,
        ece: false,
        urg: false,
        ack: false,
        psh: false,
        rst: false,
        syn: false,
        fin: false,
      },
      windowSize: 0,
    });

    const ipv4Zero = encodeTCP(zeroTcp, {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: {
        status: 'valid',
        version: 4,
        srcIp: new Uint8Array([0, 0, 0, 0]),
        dstIp: new Uint8Array([0, 0, 0, 0]),
      },
    });
    expect(ipv4Zero.ok).toBe(true);
    if (!ipv4Zero.ok) return;
    expect(ipv4Zero.bytes.slice(16, 18)).toEqual(new Uint8Array([0x00, 0x00]));
    expect(ipv4Zero.resolvedAutoValues.checksum).toBe(0x0000);

    const ipv6Zero = encodeTCP(zeroTcp, {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: {
        status: 'valid',
        version: 6,
        srcIp: new Uint8Array(16),
        dstIp: new Uint8Array(16),
      },
    });
    expect(ipv6Zero.ok).toBe(true);
    if (!ipv6Zero.ok) return;
    expect(ipv6Zero.bytes.slice(16, 18)).toEqual(new Uint8Array([0x00, 0x00]));
    expect(ipv6Zero.resolvedAutoValues.checksum).toBe(0x0000);
  });

  it('すべての Control Bits（8 ビット、RFC 9293）を正しいビット位置へ配置する', () => {
    const allOn = encodeTCP(
      makeBaseTCP({
        flags: {
          cwr: true,
          ece: true,
          urg: true,
          ack: true,
          psh: true,
          rst: true,
          syn: true,
          fin: true,
        },
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(allOn.ok && allOn.bytes[13]).toBe(0xff);

    const ackPsh = encodeTCP(
      makeBaseTCP({
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
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(ackPsh.ok && ackPsh.bytes[13]).toBe(0x18);
  });

  it('手動指定の Data Offset / Checksum を優先し警告を出す', () => {
    const result = encodeTCP(
      makeBaseTCP({
        dataOffset: manualValue(4),
        checksum: manualValue(0xdead),
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes[12]).toBe(0x40);
    expect(result.bytes.slice(16, 18)).toEqual(new Uint8Array([0xde, 0xad]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual(['dataOffset', 'checksum']);
  });

  it('範囲外の 32 ビット値・4 ビット値・ポート番号をエラーにする', () => {
    const result = encodeTCP(
      makeBaseTCP({
        srcPort: -1,
        dstPort: 65536,
        seqNumber: 0x100000000,
        ackNumber: -1,
        dataOffset: manualValue(16),
        windowSize: 70000,
        checksum: manualValue(-1),
        urgentPointer: 70000,
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'srcPort',
      'dstPort',
      'seqNumber',
      'ackNumber',
      'windowSize',
      'urgentPointer',
      'checksum',
      'dataOffset',
    ]);
  });

  it('TCP セグメント長 65535 バイトは成功し、65536 バイトは fieldId なしのエラーになる', () => {
    const okMax = encodeTCP(makeBaseTCP(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(65515), // 20 + 65515 = 65535
      ip: validIPv4,
    });
    expect(okMax.ok).toBe(true);

    const overflow = encodeTCP(makeBaseTCP(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(65516), // 20 + 65516 = 65536
      ip: { status: 'absent' },
    });
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors).toHaveLength(1);
      expect(overflow.errors[0].fieldId).toBeUndefined();
      expect(overflow.errors[0].message).toContain('65535');
    }
  });
});
