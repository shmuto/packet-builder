import { describe, expect, it } from 'vitest';
import {
  concatBytes,
  decodeUtf8Strict,
  encodeUtf8,
  formatIPv4,
  formatMac,
  parseHexBytes,
  parseHexOrDump,
  parseIPv4,
  parseMac,
  readUint16BE,
  readUint32BE,
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

describe('encodeUtf8 / decodeUtf8Strict / concatBytes', () => {
  it('ASCII およびマルチバイト UTF-8 文字列をバイト列へ変換する', () => {
    expect(encodeUtf8('')).toEqual(new Uint8Array(0));
    expect(encodeUtf8('Hello')).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    // "あ" = E3 81 82
    expect(encodeUtf8('あ')).toEqual(new Uint8Array([0xe3, 0x81, 0x82]));
  });

  it('decodeUtf8Strict preserves valid UTF-8 including leading BOM and rejects invalid sequences', () => {
    expect(decodeUtf8Strict(new Uint8Array(0))).toEqual({ ok: true, value: '' });
    expect(decodeUtf8Strict(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]))).toEqual({
      ok: true,
      value: 'Hello',
    });
    expect(decodeUtf8Strict(new Uint8Array([0xe3, 0x81, 0x82]))).toEqual({
      ok: true,
      value: 'あ',
    });

    // Leading UTF-8 BOM (ef bb bf) must be preserved on round-trip
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, 0x41]);
    const decodedBom = decodeUtf8Strict(withBom);
    expect(decodedBom).toEqual({ ok: true, value: '\uFEFFA' });
    if (decodedBom.ok) {
      expect(encodeUtf8(decodedBom.value)).toEqual(withBom);
    }

    // Invalid UTF-8 byte sequences must fail
    expect(decodeUtf8Strict(new Uint8Array([0xde, 0xad, 0xbe, 0xef])).ok).toBe(false);
    expect(decodeUtf8Strict(new Uint8Array([0xe3, 0x81])).ok).toBe(false);
    expect(decodeUtf8Strict(new Uint8Array([0xff])).ok).toBe(false);
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

  it('65536 バイトまでは 4 桁、65537 バイト以上は全行を 5 桁オフセットで揃える', () => {
    // ちょうど 65536 バイト: 最終行オフセットは 0xfff0（4 桁）
    const lines65536 = toHexDump(new Uint8Array(65536)).split('\n');
    expect(lines65536).toHaveLength(4096);
    expect(lines65536[0].startsWith('0000: ')).toBe(true);
    expect(lines65536[lines65536.length - 1].startsWith('fff0: ')).toBe(true);

    // 65537 バイト: 最終行オフセットは 0x10000（5 桁）→ 先頭行も 00000: で揃う
    const bytes65537 = new Uint8Array(65537);
    bytes65537[65536] = 0xab;
    const lines65537 = toHexDump(bytes65537).split('\n');
    expect(lines65537).toHaveLength(4097);
    expect(lines65537[0].startsWith('00000: ')).toBe(true);
    expect(lines65537[lines65537.length - 2].startsWith('0fff0: ')).toBe(true);
    expect(lines65537[lines65537.length - 1]).toBe('10000: ab');

    // Ethernet(14B) + IPv4 最大長(65535B) = 65549 バイトでも列がずれない
    const lines65549 = toHexDump(new Uint8Array(65549)).split('\n');
    expect(lines65549[0].startsWith('00000: ')).toBe(true);
    expect(lines65549[lines65549.length - 1].startsWith('10000: ')).toBe(true);
  });
});

describe('parseHexOrDump / readUintBE / formatMac / formatIPv4', () => {
  it('parseHexOrDump accepts both compact hex and offset-prefixed hex dumps', () => {
    const dump = ['0000: 00 11 22 33', '0010: aa bb cc'].join('\n');
    expect(parseHexOrDump(dump)).toEqual({
      ok: true,
      value: new Uint8Array([0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc]),
    });
    expect(parseHexOrDump('deadbeef')).toEqual({
      ok: true,
      value: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    });
    // Colon-separated MAC-style text (2-digit prefix) is rejected rather than misread as an offset
    expect(parseHexOrDump('aa:bb:cc').ok).toBe(false);
  });

  it('readUint16BE and readUint32BE read unsigned big-endian integers and validate bounds', () => {
    const buf = new Uint8Array([0x08, 0x06, 0xff, 0xff, 0xff, 0xff]);
    expect(readUint16BE(buf, 0)).toBe(0x0806);
    expect(readUint32BE(buf, 2)).toBe(0xffffffff);

    expect(() => readUint16BE(buf, -1)).toThrow(RangeError);
    expect(() => readUint16BE(buf, 5)).toThrow(RangeError);
    expect(() => readUint32BE(buf, -1)).toThrow(RangeError);
    expect(() => readUint32BE(buf, 3)).toThrow(RangeError);
  });

  it('formatMac and formatIPv4 format fixed-length byte arrays and reject wrong lengths', () => {
    expect(formatMac(new Uint8Array([0x00, 0x0a, 0x1b, 0x2c, 0x3d, 0xff]))).toBe(
      '00:0a:1b:2c:3d:ff',
    );
    expect(formatIPv4(new Uint8Array([192, 168, 0, 1]))).toBe('192.168.0.1');

    expect(() => formatMac(new Uint8Array(5))).toThrow(RangeError);
    expect(() => formatIPv4(new Uint8Array(3))).toThrow(RangeError);
  });
});
