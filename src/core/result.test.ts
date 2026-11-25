import { describe, expect, it } from 'vitest';
import { err, ok } from './result';

describe('result', () => {
  it('ok は成功結果を返す', () => {
    expect(ok(123)).toEqual({ ok: true, value: 123 });
  });

  it('err はエラー結果を返す', () => {
    expect(err('エラー内容')).toEqual({ ok: false, error: 'エラー内容' });
  });
});
