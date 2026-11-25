import { describe, expect, it } from 'vitest';
import { parseIPv4, parseMac, toHexDump } from './bytes';

describe('parseMac', () => {
  it('小文字の MAC アドレスを 6 バイトに変換できる', () => {
    const result = parseMac('aa:bb:cc:dd:ee:ff');
    expect(result).toEqual({
      ok: true,
      value: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    });
  });

  it('大文字および大文字・小文字混在の MAC アドレスを受け付ける', () => {
    expect(parseMac('AA:BB:CC:DD:EE:FF')).toEqual({
      ok: true,
      value: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    });
    expect(parseMac('0a:1B:2c:3D:4e:5F')).toEqual({
      ok: true,
      value: new Uint8Array([0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]),
    });
  });

  it('境界値 00:00:00:00:00:00 と ff:ff:ff:ff:ff:ff を変換できる', () => {
    expect(parseMac('00:00:00:00:00:00')).toEqual({
      ok: true,
      value: new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    });
    expect(parseMac('ff:ff:ff:ff:ff:ff')).toEqual({
      ok: true,
      value: new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    });
  });

  it.each([
    ['空文字', ''],
    ['区切りが足りない', 'aa:bb:cc:dd:ee'],
    ['区切りが多い', 'aa:bb:cc:dd:ee:ff:00'],
    ['桁が多い', 'aaa:bb:cc:dd:ee:ff'],
    ['桁が足りない', 'a:bb:cc:dd:ee:ff'],
    ['16 進以外の文字を含む', 'gg:bb:cc:dd:ee:ff'],
    ['記号を含む', 'aa:bb:cc:dd:ee:f-'],
    ['ハイフン区切り', 'aa-bb-cc-dd-ee-ff'],
    ['前後に空白を含む', ' aa:bb:cc:dd:ee:ff '],
  ])('不正な入力（%s: %s）は例外を投げずエラーを返す', (_label, input) => {
    const result = parseMac(input);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.length).toBeGreaterThan(0);
    }
  });
});

describe('parseIPv4', () => {
  it('通常の IPv4 アドレスを 4 バイトに変換できる', () => {
    expect(parseIPv4('192.168.0.1')).toEqual({
      ok: true,
      value: new Uint8Array([192, 168, 0, 1]),
    });
  });

  it('境界値 0.0.0.0 と 255.255.255.255 を変換できる', () => {
    expect(parseIPv4('0.0.0.0')).toEqual({
      ok: true,
      value: new Uint8Array([0, 0, 0, 0]),
    });
    expect(parseIPv4('255.255.255.255')).toEqual({
      ok: true,
      value: new Uint8Array([255, 255, 255, 255]),
    });
  });

  it.each([
    ['255 を超える値', '256.0.0.1'],
    ['オクテット不足', '1.2.3'],
    ['オクテット超過', '1.2.3.4.5'],
    ['先頭ゼロあり', '01.2.3.4'],
    ['0 の重複', '1.00.3.4'],
    ['空文字', ''],
    ['空のオクテット', '1..3.4'],
    ['負数', '-1.2.3.4'],
    ['プラス符号', '+1.2.3.4'],
    ['数字以外を含む', '1.2.3.a'],
    ['前後に空白を含む', ' 1.2.3.4'],
  ])('不正な入力（%s: %s）は例外を投げずエラーを返す', (_label, input) => {
    const result = parseIPv4(input);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.length).toBeGreaterThan(0);
    }
  });
});

describe('toHexDump', () => {
  it('空のデータに対して空文字列を返す', () => {
    expect(toHexDump(new Uint8Array(0))).toBe('');
  });

  it('ちょうど 16 バイトを 1 行の 16 進ダンプにする', () => {
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      bytes[i] = i;
    }
    expect(toHexDump(bytes)).toBe(
      '0000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f',
    );
  });

  it('17 バイトを 2 行に分けてオフセット付きで出力する', () => {
    const bytes = new Uint8Array(17);
    for (let i = 0; i < 17; i++) {
      bytes[i] = i;
    }
    expect(toHexDump(bytes)).toBe(
      [
        '0000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f',
        '0010: 10',
      ].join('\n'),
    );
  });

  it('16 バイト未満のデータもゼロ埋めの 2 桁 16 進数で出力する', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xab, 0xff]);
    expect(toHexDump(bytes)).toBe('0000: 00 0f ab ff');
  });
});
