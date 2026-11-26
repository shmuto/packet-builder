import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseIPv6 } from '../bytes';
import { autoValue, manualValue } from './types';
import { encodeUDP } from './udp';

function mustIPv6(addr: string): Uint8Array {
  const res = parseIPv6(addr);
  if (!res.ok) throw new Error(res.error);
  return res.value;
}

describe('encodeUDP', () => {
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

  it('IPv4 擬似ヘッダ込みの UDP ヘッダを正しく組み立てる', () => {
    const result = encodeUDP(
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
      { layerIndex: 0, upperBytes: encodeUtf8('Hello'), ip: validIPv4 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(new Uint8Array([0x30, 0x39, 0x00, 0x50, 0x00, 0x0d, 0x2a, 0x25]));
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ length: 13, checksum: 0x2a25 });
  });

  it('IPv6 擬似ヘッダ込みの UDP ヘッダを正しく組み立てる（RFC 8200 §8.1）', () => {
    // Hand verification:
    // src=2001:db8::1 (0x2dba) + dst=2001:db8::2 (0x2dbb) + len=0x000d + nh=0x0011 = 0x5b93
    // UDP: 0x3039 + 0x0050 + 0x000d = 0x3096; "Hello" padded: 0x4865 + 0x6c6c + 0x6f00 = 0x123d1
    // sum = 0x1affa -> fold: 0xaffa + 1 = 0xaffb -> ~0xaffb = 0x5004
    const result = encodeUDP(
      {
        type: 'udp',
        srcPort: 12345,
        dstPort: 80,
        length: autoValue(),
        checksum: autoValue(),
      },
      { layerIndex: 0, upperBytes: encodeUtf8('Hello'), ip: validIPv6 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(new Uint8Array([0x30, 0x39, 0x00, 0x50, 0x00, 0x0d, 0x50, 0x04]));
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ length: 13, checksum: 0x5004 });
  });

  it('チェックサム計算結果が 0 になる場合は IPv4/IPv6 ともに 0xffff を格納する', () => {
    const ipv4Zero = encodeUDP(
      {
        type: 'udp',
        srcPort: 0xffde,
        dstPort: 0,
        length: autoValue(),
        checksum: autoValue(),
      },
      {
        layerIndex: 0,
        upperBytes: new Uint8Array(0),
        ip: {
          status: 'valid',
          version: 4,
          srcIp: new Uint8Array([0, 0, 0, 0]),
          dstIp: new Uint8Array([0, 0, 0, 0]),
        },
      },
    );

    expect(ipv4Zero.ok).toBe(true);
    if (!ipv4Zero.ok) return;
    expect(ipv4Zero.bytes.slice(6, 8)).toEqual(new Uint8Array([0xff, 0xff]));
    expect(ipv4Zero.resolvedAutoValues.checksum).toBe(0xffff);

    const ipv6Zero = encodeUDP(
      {
        type: 'udp',
        srcPort: 0xffde,
        dstPort: 0,
        length: autoValue(),
        checksum: autoValue(),
      },
      {
        layerIndex: 0,
        upperBytes: new Uint8Array(0),
        ip: {
          status: 'valid',
          version: 6,
          srcIp: new Uint8Array(16),
          dstIp: new Uint8Array(16),
        },
      },
    );

    expect(ipv6Zero.ok).toBe(true);
    if (!ipv6Zero.ok) return;
    expect(ipv6Zero.bytes.slice(6, 8)).toEqual(new Uint8Array([0xff, 0xff]));
    expect(ipv6Zero.resolvedAutoValues.checksum).toBe(0xffff);
  });

  it('UDP 長 65535 バイトは成功し、65536 バイトはエラーになる', () => {
    const okMax = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: autoValue(),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(65527), ip: validIPv4 },
    );
    expect(okMax.ok).toBe(true);

    const overflow = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: autoValue(),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(65528), ip: validIPv4 },
    );
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.fieldId === 'length')).toBe(true);
    }
  });

  it('手動指定の length / checksum を優先し、IPv4 の 0x0000 には未使用警告、IPv6 の 0x0000 には RFC 8200 §8.1 必須警告を出す', () => {
    const result = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: manualValue(4),
        checksum: manualValue(0x0000),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(4, 8)).toEqual(new Uint8Array([0x00, 0x04, 0x00, 0x00]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual(['length', 'checksum']);
    const checksumWarning = result.warnings.find((w) => w.fieldId === 'checksum');
    expect(checksumWarning?.message).toContain('disabled / unused');
    expect(checksumWarning?.message).not.toContain('computed value');

    // Manual 0x0000 over IPv6 must cite RFC 8200 §8.1 and NOT reuse IPv4 "disabled / unused" wording
    const ipv6ZeroManual = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: manualValue(0x0000),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv6 },
    );
    expect(ipv6ZeroManual.ok).toBe(true);
    if (!ipv6ZeroManual.ok) return;
    expect(ipv6ZeroManual.bytes.slice(6, 8)).toEqual(new Uint8Array([0x00, 0x00]));
    const ipv6ZeroWarn = ipv6ZeroManual.warnings.find((w) => w.fieldId === 'checksum');
    expect(ipv6ZeroWarn?.message).toContain('RFC 8200 §8.1');
    expect(ipv6ZeroWarn?.message).toContain('mandatory');
    expect(ipv6ZeroWarn?.message).not.toContain('disabled / unused');

    // Non-zero manual checksum mismatch should report the computed value
    const mismatched = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: manualValue(0x1234),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: validIPv4 },
    );
    expect(mismatched.ok).toBe(true);
    if (!mismatched.ok) return;
    const mismatchWarning = mismatched.warnings.find((w) => w.fieldId === 'checksum');
    expect(mismatchWarning?.message).toContain('computed value is');
  });

  it('下位 IPv4/IPv6 がない場合は checksum=0x0000 として警告を出す', () => {
    const result = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: autoValue(),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: { status: 'absent' } },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(6, 8)).toEqual(new Uint8Array([0x00, 0x00]));
    expect(result.warnings.some((w) => w.fieldId === 'checksum')).toBe(true);
  });
});
