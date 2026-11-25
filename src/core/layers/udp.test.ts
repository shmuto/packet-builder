import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from '../bytes';
import { autoValue, manualValue } from './types';
import { encodeUDP } from './udp';

describe('encodeUDP', () => {
  const validIPv4 = {
    status: 'valid' as const,
    srcIp: new Uint8Array([192, 168, 0, 1]),
    dstIp: new Uint8Array([192, 168, 0, 2]),
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
      { layerIndex: 0, upperBytes: encodeUtf8('Hello'), ipv4: validIPv4 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(new Uint8Array([0x30, 0x39, 0x00, 0x50, 0x00, 0x0d, 0x2a, 0x25]));
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ length: 13, checksum: 0x2a25 });
  });

  it('チェックサム計算結果が 0 になる場合は RFC 768 に従い 0xffff を格納する', () => {
    const result = encodeUDP(
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
        ipv4: {
          status: 'valid',
          srcIp: new Uint8Array([0, 0, 0, 0]),
          dstIp: new Uint8Array([0, 0, 0, 0]),
        },
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(6, 8)).toEqual(new Uint8Array([0xff, 0xff]));
    expect(result.resolvedAutoValues.checksum).toBe(0xffff);
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
      { layerIndex: 0, upperBytes: new Uint8Array(65527), ipv4: validIPv4 },
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
      { layerIndex: 0, upperBytes: new Uint8Array(65528), ipv4: validIPv4 },
    );
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.fieldId === 'length')).toBe(true);
    }
  });

  it('手動指定の length / checksum を優先し、0x0000 には未使用の専用警告を出す', () => {
    const result = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: manualValue(4),
        checksum: manualValue(0x0000),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: validIPv4 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(4, 8)).toEqual(new Uint8Array([0x00, 0x04, 0x00, 0x00]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual(['length', 'checksum']);
    const checksumWarning = result.warnings.find((w) => w.fieldId === 'checksum');
    expect(checksumWarning?.message).toContain('disabled / unused');
    expect(checksumWarning?.message).not.toContain('computed value');

    // Non-zero manual checksum mismatch should report the computed value
    const mismatched = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: manualValue(0x1234),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: validIPv4 },
    );
    expect(mismatched.ok).toBe(true);
    if (!mismatched.ok) return;
    const mismatchWarning = mismatched.warnings.find((w) => w.fieldId === 'checksum');
    expect(mismatchWarning?.message).toContain('computed value is');
  });

  it('下位 IPv4 がない場合は checksum=0x0000 として警告を出す', () => {
    const result = encodeUDP(
      {
        type: 'udp',
        srcPort: 1000,
        dstPort: 2000,
        length: autoValue(),
        checksum: autoValue(),
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ipv4: { status: 'absent' } },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(6, 8)).toEqual(new Uint8Array([0x00, 0x00]));
    expect(result.warnings.some((w) => w.fieldId === 'checksum')).toBe(true);
  });
});
