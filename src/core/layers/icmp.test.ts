import { describe, expect, it } from 'vitest';
import { concatBytes, encodeUtf8 } from '../bytes';
import { internetChecksum } from '../checksum';
import { encodeICMP } from './icmp';
import { autoValue, manualValue } from './types';

describe('encodeICMP', () => {
  it('ICMP Echo Request ヘッダを組み立て、ペイロード込みのチェックサムが一致する', () => {
    const payload = encodeUtf8('ping');
    const result = encodeICMP(
      {
        type: 'icmp',
        icmpType: 8,
        code: 0,
        checksum: autoValue(),
        identifier: 1,
        sequenceNumber: 1,
      },
      { layerIndex: 0, upperBytes: payload },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(new Uint8Array([0x08, 0x00, 0x19, 0x2d, 0x00, 0x01, 0x00, 0x01]));
    expect(internetChecksum(concatBytes(result.bytes, payload))).toBe(0);
    expect(result.warnings).toHaveLength(0);
  });

  it('ペイロード 0 バイトおよび手動チェックサム上書きを正しく扱える', () => {
    const result = encodeICMP(
      {
        type: 'icmp',
        icmpType: 8,
        code: 0,
        checksum: manualValue(0x1234),
        identifier: 0,
        sequenceNumber: 0,
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0) },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(2, 4)).toEqual(new Uint8Array([0x12, 0x34]));
    expect(result.resolvedAutoValues.checksum).toBe(0xf7ff);
    expect(result.warnings.some((w) => w.fieldId === 'checksum')).toBe(true);
  });

  it('範囲外のフィールドはエラーを返す', () => {
    const result = encodeICMP(
      {
        type: 'icmp',
        icmpType: 256,
        code: -1,
        checksum: manualValue(0x10000),
        identifier: 70000,
        sequenceNumber: -5,
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0) },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'icmpType',
      'code',
      'identifier',
      'sequenceNumber',
      'checksum',
    ]);
  });
});
