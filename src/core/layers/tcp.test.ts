import { describe, expect, it } from 'vitest';
import { encodeTCP } from './tcp';
import { autoValue, manualValue, type TCPLayer } from './types';

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
    ...overrides,
  };
}

describe('encodeTCP', () => {
  const validIPv4 = {
    status: 'valid' as const,
    srcIp: new Uint8Array([192, 168, 0, 1]),
    dstIp: new Uint8Array([192, 168, 0, 2]),
  };

  it('TCP SYN ヘッダ（20 バイト）と擬似ヘッダチェックサムを正しく組み立てる', () => {
    const result = encodeTCP(makeBaseTCP(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ipv4: validIPv4,
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

  it('チェックサム計算結果が 0x0000 になる場合、RFC 9293 に従い 0x0000 のまま格納する', () => {
    const result = encodeTCP(
      makeBaseTCP({
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
      }),
      {
        layerIndex: 0,
        upperBytes: new Uint8Array(0),
        ipv4: {
          status: 'valid',
          srcIp: new Uint8Array([0, 0, 0, 0]),
          dstIp: new Uint8Array([0, 0, 0, 0]),
        },
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(16, 18)).toEqual(new Uint8Array([0x00, 0x00]));
    expect(result.resolvedAutoValues.checksum).toBe(0x0000);
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
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: validIPv4 },
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
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: validIPv4 },
    );
    expect(ackPsh.ok && ackPsh.bytes[13]).toBe(0x18);
  });

  it('手動指定の Data Offset / Checksum を優先し警告を出す', () => {
    const result = encodeTCP(
      makeBaseTCP({
        dataOffset: manualValue(4),
        checksum: manualValue(0xdead),
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: validIPv4 },
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
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: validIPv4 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'srcPort',
      'dstPort',
      'seqNumber',
      'ackNumber',
      'dataOffset',
      'windowSize',
      'urgentPointer',
      'checksum',
    ]);
  });
});
