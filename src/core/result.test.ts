import { describe, expect, it } from 'vitest';
import { err, ok } from './result';

describe('result', () => {
  it('ok は成功結果を返す', () => {
    const result = ok(42);
    expect(result).toEqual({ ok: true, value: 42 });
  });

  it('err はエラー結果を返す', () => {
    const result = err('不正な値です');
    expect(result).toEqual({ ok: false, error: '不正な値です' });
  });
});
