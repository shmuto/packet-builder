import { describe, expect, it } from 'vitest';
import {
  concatBytes,
  encodeUtf8,
  parseHexBytes,
  parseIPv4,
  parseMac,
  toHexDump,
  toHexString,
  writeUint16BE,
  writeUint32BE,
} from './bytes';

describe('parseMac', () => {
  it('小文字・大文字・混在の MAC アドレスを 6 バイトに変換できる', () => {
    expect(parseMac('aa:bb:cc:dd:ee:ff')).toEqual({
      ok: true,
      value: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    });
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
    ['区切り不足', 'aa:bb:cc:dd:ee'],
    ['区切り過多', 'aa:bb:cc:dd:ee:ff:00'],
    ['桁超過', 'aaa:bb:cc:dd:ee:ff'],
    ['桁不足', 'a:bb:cc:dd:ee:ff'],
    ['16 進以外', 'gg:bb:cc:dd:ee:ff'],
    ['ハイフン区切り', 'aa-bb-cc-dd-ee-ff'],
    ['前後の空白', ' aa:bb:cc:dd:ee:ff '],
  ])('不正な入力（%s: %s）はエラーを返す', (_label, input) => {
    const result = parseMac(input);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.length).toBeGreaterThan(0);
    }
  });
});

describe('parseIPv4', () => {
  it('通常の IPv4 アドレスおよび境界値を 4 バイトに変換できる', () => {
    expect(parseIPv4('192.168.0.1')).toEqual({
      ok: true,
      value: new Uint8Array([192, 168, 0, 1]),
    });
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
    ['255 超過', '256.0.0.1'],
    ['オクテット不足', '1.2.3'],
    ['オクテット超過', '1.2.3.4.5'],
    ['先頭ゼロ', '01.2.3.4'],
    ['0 の重複', '1.00.3.4'],
    ['空文字', ''],
    ['空のオクテット', '1..3.4'],
    ['負数', '-1.2.3.4'],
    ['プラス符号', '+1.2.3.4'],
    ['数字以外', '1.2.3.a'],
    ['空白含む', ' 1.2.3.4'],
  ])('不正な入力（%s: %s）はエラーを返す', (_label, input) => {
    const result = parseIPv4(input);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.length).toBeGreaterThan(0);
    }
  });
});

describe('parseHexBytes', () => {
  it('空文字・空白のみは長さ 0 のバイト列を返す', () => {
    expect(parseHexBytes('')).toEqual({ ok: true, value: new Uint8Array(0) });
    expect(parseHexBytes('   \n\t  ')).toEqual({ ok: true, value: new Uint8Array(0) });
  });

  it('連続・空白区切り・改行区切り・大文字小文字混在を変換できる', () => {
    expect(parseHexBytes('48656c6c6f')).toEqual({
      ok: true,
      value: new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]),
    });
    expect(parseHexBytes('00 0a\nFF\t1b')).toEqual({
      ok: true,
      value: new Uint8Array([0x00, 0x0a, 0xff, 0x1b]),
    });
  });

  it('奇数桁や 16 進文字以外はエラーを返す', () => {
    expect(parseHexBytes('abc').ok).toBe(false);
    expect(parseHexBytes('00 zz').ok).toBe(false);
    expect(parseHexBytes('aa:bb').ok).toBe(false);
  });
});

describe('encodeUtf8 / concatBytes', () => {
  it('ASCII およびマルチバイト UTF-8 文字列をバイト列へ変換する', () => {
    expect(encodeUtf8('')).toEqual(new Uint8Array(0));
    expect(encodeUtf8('Hello')).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    // "あ" = E3 81 82
    expect(encodeUtf8('あ')).toEqual(new Uint8Array([0xe3, 0x81, 0x82]));
  });

  it('複数配列を順序どおりに連結する', () => {
    expect(concatBytes()).toEqual(new Uint8Array(0));
    expect(
      concatBytes(new Uint8Array([1, 2]), new Uint8Array(0), new Uint8Array([3, 4, 5])),
    ).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });
});

describe('writeUint16BE / writeUint32BE', () => {
  it('ビッグエンディアンで 16 ビット・32 ビット整数を書き込める', () => {
    const buf16 = new Uint8Array(4);
    writeUint16BE(buf16, 0, 0x0800);
    writeUint16BE(buf16, 2, 0xffff);
    expect(buf16).toEqual(new Uint8Array([0x08, 0x00, 0xff, 0xff]));

    const buf32 = new Uint8Array(8);
    writeUint32BE(buf32, 0, 0x01020304);
    writeUint32BE(buf32, 4, 0xffffffff);
    expect(buf32).toEqual(new Uint8Array([0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff, 0xff]));
  });

  it('範囲外の値やオフセットは RangeError を投げる', () => {
    const buf = new Uint8Array(4);
    expect(() => writeUint16BE(buf, -1, 0)).toThrow(RangeError);
    expect(() => writeUint16BE(buf, 3, 0)).toThrow(RangeError);
    expect(() => writeUint16BE(buf, 0, -1)).toThrow(RangeError);
    expect(() => writeUint16BE(buf, 0, 0x10000)).toThrow(RangeError);
    expect(() => writeUint16BE(buf, 0, 1.5)).toThrow(RangeError);

    expect(() => writeUint32BE(buf, -1, 0)).toThrow(RangeError);
    expect(() => writeUint32BE(buf, 1, 0)).toThrow(RangeError);
    expect(() => writeUint32BE(buf, 0, -1)).toThrow(RangeError);
    expect(() => writeUint32BE(buf, 0, 0x100000000)).toThrow(RangeError);
    expect(() => writeUint32BE(buf, 0, 1.5)).toThrow(RangeError);
  });
});

describe('toHexString / toHexDump', () => {
  it('toHexString は空白なしの小文字 16 進文字列を返す', () => {
    expect(toHexString(new Uint8Array(0))).toBe('');
    expect(toHexString(new Uint8Array([0x00, 0x0a, 0xfe, 0xff]))).toBe('000afeff');
  });

  it('toHexDump は空データ・ちょうど 16 バイト・17 バイトを正しく整形する', () => {
    expect(toHexDump(new Uint8Array(0))).toBe('');

    const exact16 = new Uint8Array(16);
    for (let i = 0; i < 16; i++) exact16[i] = i;
    expect(toHexDump(exact16)).toBe(
      '0000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f',
    );

    const bytes17 = new Uint8Array(17);
    for (let i = 0; i < 17; i++) bytes17[i] = i;
    expect(toHexDump(bytes17)).toBe(
      [
        '0000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f',
        '0010: 10',
      ].join('\n'),
    );
  });
});
