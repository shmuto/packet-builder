import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseHexBytes } from './bytes';
import {
  buildBitDiagramRows,
  buildHexDumpRows,
  buildUnifiedBitDiagramRows,
  doesSpanMatchTarget,
  evaluatePacketDraft,
  findHighlightedByteIndices,
  formatByteAscii,
  formatByteBinary,
  formatHex,
  formatSpacedHex,
  isByteHighlighted,
  isFieldHighlighted,
  parseUnsignedIntInput,
  resolveHighlightedLayerIndex,
  summarizeLayerSegments,
  type BitDiagramRow,
} from './inspector';
import { buildPacket } from './packet';
import {
  createDefaultARP,
  createDefaultEthernet,
  createDefaultICMP,
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

function expectContiguousBitDiagram(rows: readonly BitDiagramRow[], expectedTotalBits: number) {
  let totalBits = 0;
  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    expect(row.rowIndex).toBe(r);
    expect(row.bitOffsetInLayer).toBe(r * 32);
    let colCursor = 0;
    for (const cell of row.cells) {
      expect(cell.colStart).toBe(colCursor);
      expect(cell.colSpan).toBeGreaterThan(0);
      expect(cell.bitLengthInRow).toBe(cell.colSpan);
      colCursor += cell.colSpan;
    }
    expect(colCursor).toBe(row.totalBitsInRow);
    expect(colCursor).toBeLessThanOrEqual(32);
    if (r < rows.length - 1) {
      expect(colCursor).toBe(32);
    }
    totalBits += colCursor;
  }
  expect(totalBits).toBe(expectedTotalBits);
}

describe('formatByteBinary & bidirectional highlight helpers', () => {
  it('formatByteBinary splits 8 bits into two 4-bit nibbles', () => {
    expect(formatByteBinary(0x00)).toBe('0000 0000');
    expect(formatByteBinary(0x45)).toBe('0100 0101');
    expect(formatByteBinary(0xff)).toBe('1111 1111');
  });

  it('highlights IPv4 Version/IHL, Flags/FragmentOffset, and TCP DataOffset/Reserved bidirectionally', () => {
    const draft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
      ok(encodeUtf8('ok')),
    );
    expect(draft.ok).toBe(true);

    // 1) IPv4 byte 0 (packet byte 14): Version (4b) + IHL (4b)
    const ipv4FirstByte = draft.rows[0].cells[14];
    const ethLastByte = draft.rows[0].cells[13];
    const versionTarget = { kind: 'field' as const, layerIndex: 1, fieldId: 'version' };
    expect(findHighlightedByteIndices(draft.spans, versionTarget)).toEqual(new Set([14]));
    expect(isByteHighlighted(ipv4FirstByte, versionTarget)).toBe(true);
    expect(isByteHighlighted(ethLastByte, versionTarget)).toBe(false);

    const byte14Target = { kind: 'byte' as const, byteIndex: 14 };
    expect(findHighlightedByteIndices(draft.spans, byte14Target)).toEqual(new Set([14]));
    expect(isFieldHighlighted(1, 'version', draft.spans, byte14Target)).toBe(true);
    expect(isFieldHighlighted(1, 'ihl', draft.spans, byte14Target)).toBe(true);
    expect(isFieldHighlighted(1, 'tos', draft.spans, byte14Target)).toBe(false);

    // 2) IPv4 byte 6..7 (packet bytes 20..21): Flags (3b) + Fragment Offset (13b) (RFC 791)
    expect(
      findHighlightedByteIndices(draft.spans, { kind: 'field', layerIndex: 1, fieldId: 'flags' }),
    ).toEqual(new Set([20]));
    expect(
      findHighlightedByteIndices(draft.spans, {
        kind: 'field',
        layerIndex: 1,
        fieldId: 'fragmentOffset',
      }),
    ).toEqual(new Set([20, 21]));
    const byte20Target = { kind: 'byte' as const, byteIndex: 20 };
    expect(isFieldHighlighted(1, 'flags', draft.spans, byte20Target)).toBe(true);
    expect(isFieldHighlighted(1, 'fragmentOffset', draft.spans, byte20Target)).toBe(true);
    expect(isFieldHighlighted(1, 'identification', draft.spans, byte20Target)).toBe(false);
    // Byte 21 belongs only to Fragment Offset (not Flags)
    const byte21Target = { kind: 'byte' as const, byteIndex: 21 };
    expect(isFieldHighlighted(1, 'flags', draft.spans, byte21Target)).toBe(false);
    expect(isFieldHighlighted(1, 'fragmentOffset', draft.spans, byte21Target)).toBe(true);

    // 3) TCP byte 12 (packet byte 46): Data Offset (4b) + Reserved (4b) (RFC 9293 Section 3.1)
    expect(
      findHighlightedByteIndices(draft.spans, {
        kind: 'field',
        layerIndex: 2,
        fieldId: 'dataOffset',
      }),
    ).toEqual(new Set([46]));
    expect(
      findHighlightedByteIndices(draft.spans, {
        kind: 'field',
        layerIndex: 2,
        fieldId: 'reserved',
      }),
    ).toEqual(new Set([46]));
    const byte46Target = { kind: 'byte' as const, byteIndex: 46 };
    expect(isFieldHighlighted(2, 'dataOffset', draft.spans, byte46Target)).toBe(true);
    expect(isFieldHighlighted(2, 'reserved', draft.spans, byte46Target)).toBe(true);
    expect(isFieldHighlighted(2, 'flags', draft.spans, byte46Target)).toBe(false);

    // doesSpanMatchTarget direct checks + null target
    const versionSpan = draft.spans.find((s) => s.layerIndex === 1 && s.fieldId === 'version')!;
    expect(doesSpanMatchTarget(versionSpan, byte14Target)).toBe(true);
    expect(doesSpanMatchTarget(versionSpan, { kind: 'byte', byteIndex: 15 })).toBe(false);
    expect(doesSpanMatchTarget(versionSpan, null)).toBe(false);
    expect(findHighlightedByteIndices(draft.spans, null)).toEqual(new Set());
  });
});

describe('buildBitDiagramRows', () => {
  it('covers Ethernet II, IPv4, TCP, UDP, and ICMP cleanly without gaps or overlaps', () => {
    const tcpDraft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
      ok(new Uint8Array(0)),
    );
    expect(tcpDraft.ok).toBe(true);

    // Ethernet II (112 bits = 32 + 32 + 32 + 16)
    const ethRows = buildBitDiagramRows(tcpDraft.spans, 0);
    expect(ethRows).toHaveLength(4);
    expectContiguousBitDiagram(ethRows, 112);
    expect(ethRows[0].cells[0]).toMatchObject({ colStart: 0, colSpan: 32, isContinuation: false });
    expect(
      ethRows[1].cells.map((c) => [c.span.fieldId, c.colStart, c.colSpan, c.isContinuation]),
    ).toEqual([
      ['dstMac', 0, 16, true],
      ['srcMac', 16, 16, false],
    ]);
    expect(ethRows[2].cells[0]).toMatchObject({ colStart: 0, colSpan: 32, isContinuation: true });
    expect(ethRows[3].cells[0]).toMatchObject({ colStart: 0, colSpan: 16, isContinuation: false });

    // IPv4 (160 bits = 5 rows of 32 bits, RFC 791)
    const ipv4Rows = buildBitDiagramRows(tcpDraft.spans, 1);
    expect(ipv4Rows).toHaveLength(5);
    expectContiguousBitDiagram(ipv4Rows, 160);
    expect(ipv4Rows[0].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['version', 4],
      ['ihl', 4],
      ['tos', 8],
      ['totalLength', 16],
    ]);
    expect(ipv4Rows[1].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['identification', 16],
      ['flags', 3],
      ['fragmentOffset', 13],
    ]);

    // TCP (160 bits = 5 rows of 32 bits, RFC 9293 Section 3.1)
    const tcpRows = buildBitDiagramRows(tcpDraft.spans, 2);
    expect(tcpRows).toHaveLength(5);
    expectContiguousBitDiagram(tcpRows, 160);
    expect(tcpRows[3].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['dataOffset', 4],
      ['reserved', 4],
      ['flags', 8],
      ['windowSize', 16],
    ]);

    // UDP (64 bits = 2 rows of 32 bits, RFC 768)
    const udpDraft = evaluatePacketDraft(
      [createDefaultIPv4(), createDefaultUDP()],
      ok(new Uint8Array(0)),
    );
    expect(udpDraft.ok).toBe(true);
    const udpRows = buildBitDiagramRows(udpDraft.spans, 1);
    expect(udpRows).toHaveLength(2);
    expectContiguousBitDiagram(udpRows, 64);
    expect(udpRows[0].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['srcPort', 16],
      ['dstPort', 16],
    ]);
    expect(udpRows[1].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['length', 16],
      ['checksum', 16],
    ]);

    // ICMP (64 bits = 2 rows of 32 bits, RFC 792)
    const icmpDraft = evaluatePacketDraft(
      [createDefaultIPv4(), createDefaultICMP()],
      ok(new Uint8Array(0)),
    );
    expect(icmpDraft.ok).toBe(true);
    const icmpRows = buildBitDiagramRows(icmpDraft.spans, 1);
    expect(icmpRows).toHaveLength(2);
    expectContiguousBitDiagram(icmpRows, 64);
    expect(icmpRows[0].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['icmpType', 8],
      ['code', 8],
      ['checksum', 16],
    ]);
    expect(icmpRows[1].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['identifier', 16],
      ['sequenceNumber', 16],
    ]);

    // ARP (224 bits = 7 rows of 32 bits, RFC 826, wraps 48-bit MAC & 32-bit IP across 32-bit rows)
    const arpDraft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultARP()],
      ok(new Uint8Array(0)),
    );
    expect(arpDraft.ok).toBe(true);
    const arpRows = buildBitDiagramRows(arpDraft.spans, 1);
    expect(arpRows).toHaveLength(7);
    expectContiguousBitDiagram(arpRows, 224);
    expect(arpRows[0].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['hardwareType', 16],
      ['protocolType', 16],
    ]);
    expect(arpRows[1].cells.map((c) => [c.span.fieldId, c.colSpan])).toEqual([
      ['hardwareLength', 8],
      ['protocolLength', 8],
      ['operation', 16],
    ]);
    expect(
      arpRows[3].cells.map((c) => [c.span.fieldId, c.colStart, c.colSpan, c.isContinuation]),
    ).toEqual([
      ['senderMac', 0, 16, true],
      ['senderIp', 16, 16, false],
    ]);
    expect(
      arpRows[4].cells.map((c) => [c.span.fieldId, c.colStart, c.colSpan, c.isContinuation]),
    ).toEqual([
      ['senderIp', 0, 16, true],
      ['targetMac', 16, 16, false],
    ]);

    // Missing layer index returns empty array
    expect(buildBitDiagramRows(tcpDraft.spans, 99)).toEqual([]);
  });
});

describe('buildUnifiedBitDiagramRows & layer range highlighting', () => {
  it('lays out all headers continuously in wire order with exact layer start/end boundaries and excludes Payload', () => {
    const draft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()],
      ok(encodeUtf8('Hello')),
    );
    expect(draft.ok).toBe(true);

    // Ethernet (14B=112b) + IPv4 (20B=160b) + UDP (8B=64b) = 42B = 336 bits -> 11 rows (10x32 + 16)
    const rows = buildUnifiedBitDiagramRows(draft.spans);
    expect(rows).toHaveLength(11);

    let totalBits = 0;
    for (let r = 0; r < rows.length; r++) {
      const row = rows[r];
      expect(row.rowIndex).toBe(r);
      expect(row.bitOffset).toBe(r * 32);
      expect(row.byteOffset).toBe(r * 4);
      let colCursor = 0;
      for (const cell of row.cells) {
        expect(cell.span.section).toBe('layer');
        expect(cell.colStart).toBe(colCursor);
        expect(cell.colSpan).toBeGreaterThan(0);
        expect(cell.bitLengthInRow).toBe(cell.colSpan);
        colCursor += cell.colSpan;
      }
      expect(colCursor).toBe(row.totalBitsInRow);
      if (r < rows.length - 1) {
        expect(colCursor).toBe(32);
      }
      totalBits += colCursor;
    }
    expect(totalBits).toBe(336);

    // Row 0: Ethernet starts at bit 0
    expect(rows[0].cells[0]).toMatchObject({
      colStart: 0,
      colSpan: 32,
      isLayerStart: true,
      isLayerEnd: false,
    });

    // Row 3 (bit 96): mid-row boundary from Ethernet EtherType -> IPv4 Version/IHL/TOS
    expect(
      rows[3].cells.map((c) => [
        c.span.layerType,
        c.span.fieldId,
        c.colStart,
        c.colSpan,
        c.isLayerStart,
        c.isLayerEnd,
      ]),
    ).toEqual([
      ['ethernet', 'etherType', 0, 16, false, true],
      ['ipv4', 'version', 16, 4, true, false],
      ['ipv4', 'ihl', 20, 4, false, false],
      ['ipv4', 'tos', 24, 8, false, false],
    ]);

    // Row 8 (bit 256): mid-row boundary from IPv4 dstIp (cont.) -> UDP srcPort
    expect(
      rows[8].cells.map((c) => [
        c.span.layerType,
        c.span.fieldId,
        c.colStart,
        c.colSpan,
        c.isContinuation,
        c.isLayerStart,
        c.isLayerEnd,
      ]),
    ).toEqual([
      ['ipv4', 'dstIp', 0, 16, true, false, true],
      ['udp', 'srcPort', 16, 16, false, true, false],
    ]);

    // Row 10 (bit 320): UDP checksum ends the header block
    expect(rows[10].cells).toHaveLength(1);
    expect(rows[10].cells[0]).toMatchObject({
      colStart: 0,
      colSpan: 16,
      isLayerStart: false,
      isLayerEnd: true,
    });
    expect(rows[10].cells[0].span.fieldId).toBe('checksum');
  });

  it('returns empty rows for payload-only packets and aligns Raw IPv4 + TCP cleanly on 32-bit rows', () => {
    const payloadOnly = evaluatePacketDraft([], ok(encodeUtf8('abc')));
    expect(payloadOnly.ok).toBe(true);
    expect(buildUnifiedBitDiagramRows(payloadOnly.spans)).toEqual([]);

    const rawIpTcp = evaluatePacketDraft(
      [createDefaultIPv4(), createDefaultTCP()],
      ok(new Uint8Array(0)),
    );
    expect(rawIpTcp.ok).toBe(true);
    const rows = buildUnifiedBitDiagramRows(rawIpTcp.spans);
    expect(rows).toHaveLength(10); // 160 + 160 = 320 bits
    expect(rows[0].cells[0]).toMatchObject({ isLayerStart: true });
    expect(rows[4].cells[0]).toMatchObject({ isLayerEnd: true });
    expect(rows[5].cells[0]).toMatchObject({ isLayerStart: true });
    expect(rows[9].cells[rows[9].cells.length - 1]).toMatchObject({ isLayerEnd: true });
  });

  it('supports layer-range HighlightTarget and resolves active header index across field/byte/layer targets', () => {
    const draft = evaluatePacketDraft(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()],
      ok(encodeUtf8('Hello')),
    );
    expect(draft.ok).toBe(true);

    const ipv4Target = { kind: 'layer' as const, layerIndex: 1 };
    const ipv4Bytes = findHighlightedByteIndices(draft.spans, ipv4Target);
    // IPv4 occupies bytes 14..33 (20 bytes)
    expect(ipv4Bytes.size).toBe(20);
    expect(ipv4Bytes.has(13)).toBe(false);
    expect(ipv4Bytes.has(14)).toBe(true);
    expect(ipv4Bytes.has(33)).toBe(true);
    expect(ipv4Bytes.has(34)).toBe(false);

    // doesSpanMatchTarget matches only IPv4 spans
    const ethSpan = draft.spans.find((s) => s.layerIndex === 0)!;
    const ipSpan = draft.spans.find((s) => s.layerIndex === 1 && s.fieldId === 'ttl')!;
    const payloadSpan = draft.spans.find((s) => s.section === 'payload')!;
    expect(doesSpanMatchTarget(ethSpan, ipv4Target)).toBe(false);
    expect(doesSpanMatchTarget(ipSpan, ipv4Target)).toBe(true);
    expect(doesSpanMatchTarget(payloadSpan, ipv4Target)).toBe(false);

    // Layer target should not light up individual form inputs inside LayerCard
    expect(isFieldHighlighted(1, 'ttl', draft.spans, ipv4Target)).toBe(false);

    // resolveHighlightedLayerIndex across all target kinds
    expect(resolveHighlightedLayerIndex(draft.spans, null)).toBeNull();
    expect(resolveHighlightedLayerIndex(draft.spans, ipv4Target)).toBe(1);
    expect(resolveHighlightedLayerIndex(draft.spans, { kind: 'layer', layerIndex: 99 })).toBeNull();
    expect(
      resolveHighlightedLayerIndex(draft.spans, {
        kind: 'field',
        layerIndex: 2,
        fieldId: 'srcPort',
      }),
    ).toBe(2);
    expect(
      resolveHighlightedLayerIndex(draft.spans, {
        kind: 'field',
        layerIndex: 3,
        fieldId: 'payload',
      }),
    ).toBeNull();
    expect(resolveHighlightedLayerIndex(draft.spans, { kind: 'byte', byteIndex: 14 })).toBe(1);
    expect(resolveHighlightedLayerIndex(draft.spans, { kind: 'byte', byteIndex: 42 })).toBeNull();
  });
});
