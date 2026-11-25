import { describe, expect, it } from 'vitest';
import { internetChecksum } from './checksum';

describe('internetChecksum', () => {
  it('RFC 1071 Section 3 の例と一致する', () => {
    // RFC 1071 Section 3: 00 01 f2 03 f4 f5 f6 f7 -> 1の補数和 0xddf2 -> チェックサム 0x220d
    const data = new Uint8Array([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]);
    expect(internetChecksum(data)).toBe(0x220d);
  });

  it('既知の IPv4 ヘッダ例のチェックサムと一致する', () => {
    const header = new Uint8Array([
      0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
      0x00, 0x00, // チェックサム欄は 0 で計算
      0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ]);
    expect(internetChecksum(header)).toBe(0xb861);
  });

  it('奇数長のデータは末尾に 0x00 を補って計算する', () => {
    const odd = new Uint8Array([0x00, 0x01, 0xf2]);
    const padded = new Uint8Array([0x00, 0x01, 0xf2, 0x00]);
    expect(internetChecksum(odd)).toBe(internetChecksum(padded));
    expect(internetChecksum(odd)).toBe(0x0dfe);

    // 1 バイトのみの場合も末尾に 0x00 を補って計算される
    const single = new Uint8Array([0xab]);
    expect(internetChecksum(single)).toBe(internetChecksum(new Uint8Array([0xab, 0x00])));
    expect(internetChecksum(single)).toBe(0x54ff);
  });

  it('正しいチェックサムを埋めたデータを再計算すると 0 になる', () => {
    // RFC 1071 Section 3 の例にチェックサム（0x220d）を付加
    const rfcWithChecksum = new Uint8Array([
      0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x22, 0x0d,
    ]);
    expect(internetChecksum(rfcWithChecksum)).toBe(0x0000);

    // IPv4 ヘッダ例にチェックサム（0xb861）を埋めた場合
    const ipv4WithChecksum = new Uint8Array([
      0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
      0xb8, 0x61,
      0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ]);
    expect(internetChecksum(ipv4WithChecksum)).toBe(0x0000);
  });

  it('空データやキャリー折り畳みの境界値を正しく計算する', () => {
    expect(internetChecksum(new Uint8Array(0))).toBe(0xffff);
    expect(internetChecksum(new Uint8Array([0x00, 0x00]))).toBe(0xffff);
    expect(internetChecksum(new Uint8Array([0xff, 0xff]))).toBe(0x0000);
    // 0x8000 + 0x8000 = 0x10000 -> fold -> 0x0001 -> ~0x0001 = 0xfffe
    expect(internetChecksum(new Uint8Array([0x80, 0x00, 0x80, 0x00]))).toBe(0xfffe);
    // 0xffff + 0xffff = 0x1fffe -> fold -> 0xffff -> ~0xffff = 0x0000
    expect(internetChecksum(new Uint8Array([0xff, 0xff, 0xff, 0xff]))).toBe(0x0000);
  });
});
