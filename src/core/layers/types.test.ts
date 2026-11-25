import { describe, expect, it } from 'vitest';
import { autoValue, manualValue, validateUintRange } from './types';

describe('layers/types', () => {
  it('autoValue / manualValue が期待どおりのオブジェクトを返す', () => {
    expect(autoValue()).toEqual({ mode: 'auto' });
    expect(manualValue(0x0800)).toEqual({ mode: 'manual', value: 0x0800 });
  });

  it('validateUintRange は範囲内の整数で null、範囲外・非整数でエラーメッセージを返す', () => {
    expect(validateUintRange(0, 255, 'TTL')).toBeNull();
    expect(validateUintRange(255, 255, 'TTL')).toBeNull();
    expect(validateUintRange(-1, 255, 'TTL')).not.toBeNull();
    expect(validateUintRange(256, 255, 'TTL')).not.toBeNull();
    expect(validateUintRange(1.5, 255, 'TTL')).not.toBeNull();
    expect(validateUintRange(Number.NaN, 255, 'TTL')).not.toBeNull();
    expect(validateUintRange(Number.POSITIVE_INFINITY, 255, 'TTL')).not.toBeNull();
  });
});
