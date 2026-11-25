import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseHexBytes } from './bytes';
import {
  buildHexDumpRows,
  evaluatePacketDraft,
  formatByteAscii,
  formatHex,
  formatSpacedHex,
  parseUnsignedIntInput,
  summarizeLayerSegments,
} from './inspector';
import { buildPacket } from './packet';
import {
  createDefaultEthernet,
  createDefaultIPv4,
  createDefaultTCP,
  createDefaultUDP,
} from './presets';
import { ok } from './result';

describe('parseUnsignedIntInput', () => {
  it('10 進整数と空白トリムを正しくパースできる', () => {
    expect(parseUnsignedIntInput('0')).toBe(0);
    expect(parseUnsignedIntInput(' 65535 ')).toBe(65535);
    expect(parseUnsignedIntInput('4294967295')).toBe(4294967295);
  });

  it('allowHex=true のとき 0x / 0X プレフィックス付き 16 進数を受け付ける', () => {
    expect(parseUnsignedIntInput('0x0800', true)).toBe(0x0800);
    expect(parseUnsignedIntInput('0XFFFF', true)).toBe(0xffff);
    expect(parseUnsignedIntInput('2048', true)).toBe(2048);
    // allowHex=false では 0x を拒否する
    expect(Number.isNaN(parseUnsignedIntInput('0x0800', false))).toBe(true);
  });

  it('空文字・負数・小数・指数表記・不正文字・安全範囲超は NaN を返す', () => {
    for (const bad of ['', '   ', '-1', '+1', '1.5', '1e3', '0x', '0xzz', '12abc', '99999999999999999999']) {
      expect(Number.isNaN(parseUnsignedIntInput(bad, true))).toBe(true);
    }
  });
});

describe('formatHex / formatByteAscii / formatSpacedHex', () => {
  it('formatHex は 0x 付き固定桁 16 進文字列を返す', () => {
    expect(formatHex(0, 4)).toBe('0x0000');
    expect(formatHex(0x0800, 4)).toBe('0x0800');
    expect(formatHex(17, 2)).toBe('0x11');
    expect(formatHex(-1, 4)).toBe('-');
    expect(formatHex(Number.NaN, 4)).toBe('-');
  });

  it('formatByteAscii は印字可能 ASCII（0x20〜0x7e）のみ文字として返す', () => {
    expect(formatByteAscii(0x1f)).toBe('.');
    expect(formatByteAscii(0x20)).toBe(' ');
    expect(formatByteAscii(0x41)).toBe('A');
    expect(formatByteAscii(0x7e)).toBe('~');
    expect(formatByteAscii(0x7f)).toBe('.');
    expect(formatByteAscii(0xff)).toBe('.');
  });

  it('formatSpacedHex は空白区切りの小文字 16 進文字列を返す', () => {
    expect(formatSpacedHex(new Uint8Array(0))).toBe('');
    expect(formatSpacedHex(new Uint8Array([0x00, 0x0a, 0xff]))).toBe('00 0a ff');
  });
});

describe('buildHexDumpRows / summarizeLayerSegments', () => {
  it('空のバイト列に対して空配列を返す', () => {
    expect(buildHexDumpRows(new Uint8Array(0), [])).toEqual([]);
    expect(summarizeLayerSegments([])).toEqual([]);
  });

  it('サブバイトフィールドが同じバイトへ正しく紐づき、レイヤー構成が集計される', () => {
    const built = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
      encodeUtf8('Hi!'),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const rows = buildHexDumpRows(built.bytes, built.spans);
    // 14 + 20 + 20 + 3 = 57 bytes -> 4 行（16, 16, 16, 9）
    expect(rows).toHaveLength(4);
    expect(rows.map((r) => r.offsetLabel)).toEqual(['0000', '0010', '0020', '0030']);
    expect(rows[3].cells).toHaveLength(9);

    // Byte 14 は IPv4 の先頭バイト（Version 4bit + IHL 4bit の 2 span が乗る）
    const ipv4FirstByte = rows[0].cells[14];
    expect(ipv4FirstByte.layerType).toBe('ipv4');
    expect(ipv4FirstByte.spans.map((s) => s.fieldId)).toEqual(['version', 'ihl']);

    // Byte 20 (row 1, col 4) は IPv4 Flags(3bit) + Fragment Offset(上位 5bit) の 2 span が乗る
    const ipv4FlagsByte = rows[1].cells[4];
    expect(ipv4FlagsByte.spans.map((s) => s.fieldId)).toEqual(['flags', 'fragmentOffset']);

    // Byte 46 (row 2, col 14) は TCP Data Offset(4bit) + Reserved(4bit) の 2 span が乗る
    const tcpOffsetByte = rows[2].cells[14];
    expect(tcpOffsetByte.layerType).toBe('tcp');
    expect(tcpOffsetByte.spans.map((s) => s.fieldId)).toEqual(['dataOffset', 'reserved']);

    // 末尾 3 バイトは Payload ("Hi!")
    expect(rows[3].cells.slice(6).map((c) => c.ascii).join('')).toBe('Hi!');
    expect(rows[3].cells[6].layerType).toBe('payload');

    // レイヤー構成サマリー
    expect(summarizeLayerSegments(built.spans)).toEqual([
      { layerIndex: 0, layerType: 'ethernet', byteOffset: 0, byteLength: 14 },
      { layerIndex: 1, layerType: 'ipv4', byteOffset: 14, byteLength: 20 },
      { layerIndex: 2, layerType: 'tcp', byteOffset: 34, byteLength: 20 },
      { layerIndex: 3, layerType: 'payload', byteOffset: 54, byteLength: 3 },
    ]);
  });

  it('65537 バイト以上のデータでは全行のオフセット桁数を 5 桁に揃える', () => {
    const rows = buildHexDumpRows(new Uint8Array(65537), []);
    expect(rows[0].offsetLabel).toBe('00000');
    expect(rows[rows.length - 1].offsetLabel).toBe('10000');
  });
});

describe('evaluatePacketDraft', () => {
  it('正常なレイヤーとペイロードからダンプ行・構成サマリー・自動計算値を返す', () => {
    const draft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()],
      ok(encodeUtf8('Hello, tsumiki!!!!')),
    );

    expect(draft.ok).toBe(true);
    expect(draft.bytes?.length).toBe(60);
    expect(draft.rows.length).toBeGreaterThan(0);
    expect(draft.segments).toHaveLength(4);
    expect(draft.resolvedAutoValues?.[2].length).toBe(26);
    expect(draft.warnings).toHaveLength(0);
    expect(draft.payloadError).toBeUndefined();
  });

  it('Hex ペイロードが不正なときは自動計算値・警告・ダンプ行を出さない', () => {
    const draft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()],
      parseHexBytes('48 65 6'), // 奇数桁で不正
    );

    expect(draft.ok).toBe(false);
    expect(draft.bytes).toBeNull();
    expect(draft.rows).toEqual([]);
    expect(draft.segments).toEqual([]);
    // 空ペイロード前提の AUTO 値（UDP Length=8 等）や 60B 未満警告が漏れないこと
    expect(draft.resolvedAutoValues).toBeUndefined();
    expect(draft.warnings).toEqual([]);
    expect(draft.payloadError).toBeTruthy();
  });

  it('ペイロード不正と同時にレイヤー側エラーがある場合もレイヤーエラーを保持しつつ AUTO 値と警告は抑止する', () => {
    const draft = evaluatePacketDraft(
      [{ ...createDefaultEthernet(), dstMac: 'bad' }, createDefaultIPv4(), createDefaultUDP()],
      parseHexBytes('zz'),
    );

    expect(draft.ok).toBe(false);
    expect(draft.payloadError).toBeTruthy();
    expect(draft.errors.some((e) => e.layerIndex === 0 && e.fieldId === 'dstMac')).toBe(true);
    expect(draft.resolvedAutoValues).toBeUndefined();
    expect(draft.warnings).toEqual([]);
  });
});
