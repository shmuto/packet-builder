import { describe, expect, it } from 'vitest';
import { internetChecksum } from '../checksum';
import { encodeIPv4 } from './ipv4';
import { autoValue, manualValue, type IPv4Layer } from './types';

function makeBaseIPv4(overrides: Partial<IPv4Layer> = {}): IPv4Layer {
  return {
    type: 'ipv4',
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
      totalLength: 33,
      protocol: 17,
      headerChecksum: 0xa744,
    });
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
        totalLength: manualValue(100),
        protocol: manualValue(99),
        headerChecksum: manualValue(0xbeef),
      }),
      { layerIndex: 0, upperLayerType: 'udp', upperBytesLength: 8 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(2, 4)).toEqual(new Uint8Array([0x00, 100]));
    expect(result.bytes[9]).toBe(99);
    expect(result.bytes.slice(10, 12)).toEqual(new Uint8Array([0xbe, 0xef]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual([
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
