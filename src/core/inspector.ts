import type {
  BuildPacketResult,
  FieldSpan,
  Layer,
  LayerType,
  PacketError,
  PacketWarning,
} from './layers/types';
import { buildPacket } from './packet';
import type { Result } from './result';

const DECIMAL_PATTERN = /^[0-9]+$/;
const HEX_PATTERN = /^0[xX][0-9a-fA-F]+$/;
const BYTES_PER_ROW = 16;

/**
 * フォームから入力された符号なし整数文字列をパースする。
 * 不正な形式・空文字・安全な整数範囲を超える値に対しては NaN を返す。
 */
export function parseUnsignedIntInput(raw: string, allowHex = false): number {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return Number.NaN;
  }

  let parsed: number;
  if (allowHex && HEX_PATTERN.test(trimmed)) {
    parsed = Number.parseInt(trimmed.slice(2), 16);
  } else if (DECIMAL_PATTERN.test(trimmed)) {
    parsed = Number.parseInt(trimmed, 10);
  } else {
    return Number.NaN;
  }

  return Number.isSafeInteger(parsed) ? parsed : Number.NaN;
}

/** 符号なし整数を `0x` プレフィックス付きの固定桁 16 進文字列へ整形する */
export function formatHex(value: number, digits: number): string {
  if (!Number.isInteger(value) || value < 0) {
    return '-';
  }
  return `0x${value.toString(16).padStart(digits, '0')}`;
}

/** 1 バイトを印字可能 ASCII 文字へ変換する（範囲外は '.'） */
export function formatByteAscii(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';
}

/** バイト列を空白区切りの小文字 16 進文字列（例: "48 65 6c 6c 6f"）へ変換する */
export function formatSpacedHex(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return parts.join(' ');
}

export interface HexByteCell {
  readonly byteIndex: number;
  readonly value: number;
  readonly hex: string;
  readonly ascii: string;
  readonly layerIndex: number | null;
  readonly layerType: LayerType | 'payload' | null;
  /** このバイト（8 ビット範囲）に重なるすべてのフィールド定義 */
  readonly spans: readonly FieldSpan[];
}

export interface HexDumpRow {
  readonly offset: number;
  readonly offsetLabel: string;
  readonly cells: readonly HexByteCell[];
}

/**
 * バイト列と FieldSpan[] から、16 バイト単位の 16 進ダンプ行データを生成する。
 * spans は bitOffset 昇順を前提に O(bytes.length + spans.length) で対応付ける。
 */
export function buildHexDumpRows(
  bytes: Uint8Array,
  spans: readonly FieldSpan[],
): HexDumpRow[] {
  if (bytes.length === 0) {
    return [];
  }

  const lastOffset = Math.floor((bytes.length - 1) / BYTES_PER_ROW) * BYTES_PER_ROW;
  const offsetWidth = Math.max(4, lastOffset.toString(16).length);

  const rows: HexDumpRow[] = [];
  let spanStartCursor = 0;

  for (let rowOffset = 0; rowOffset < bytes.length; rowOffset += BYTES_PER_ROW) {
    const rowEnd = Math.min(rowOffset + BYTES_PER_ROW, bytes.length);
    const cells: HexByteCell[] = [];

    for (let byteIndex = rowOffset; byteIndex < rowEnd; byteIndex++) {
      const byteStartBit = byteIndex * 8;
      const byteEndBit = byteStartBit + 8;

      // このバイトより前に完全に終わっている span をスキップ
      while (
        spanStartCursor < spans.length &&
        spans[spanStartCursor].bitOffset + spans[spanStartCursor].bitLength <= byteStartBit
      ) {
        spanStartCursor++;
      }

      const matchingSpans: FieldSpan[] = [];
      for (let s = spanStartCursor; s < spans.length; s++) {
        const span = spans[s];
        if (span.bitOffset >= byteEndBit) {
          break;
        }
        if (span.bitOffset + span.bitLength > byteStartBit) {
          matchingSpans.push(span);
        }
      }

      const primary = matchingSpans[0] ?? null;
      const value = bytes[byteIndex];
      cells.push({
        byteIndex,
        value,
        hex: value.toString(16).padStart(2, '0'),
        ascii: formatByteAscii(value),
        layerIndex: primary ? primary.layerIndex : null,
        layerType: primary ? primary.layerType : null,
        spans: matchingSpans,
      });
    }

    rows.push({
      offset: rowOffset,
      offsetLabel: rowOffset.toString(16).padStart(offsetWidth, '0'),
      cells,
    });
  }

  return rows;
}

export interface LayerSegmentSummary {
  readonly layerIndex: number;
  readonly layerType: LayerType | 'payload';
  readonly byteOffset: number;
  readonly byteLength: number;
}

/**
 * FieldSpan[] から各レイヤー（および Payload）の開始バイト位置とバイト長を集計する。
 */
export function summarizeLayerSegments(spans: readonly FieldSpan[]): LayerSegmentSummary[] {
  const segments: LayerSegmentSummary[] = [];

  for (const span of spans) {
    const last = segments[segments.length - 1];
    if (last && last.layerIndex === span.layerIndex && last.layerType === span.layerType) {
      const endBit = span.bitOffset + span.bitLength;
      segments[segments.length - 1] = {
        ...last,
        byteLength: Math.ceil(endBit / 8) - last.byteOffset,
      };
    } else {
      const byteOffset = Math.floor(span.bitOffset / 8);
      const endBit = span.bitOffset + span.bitLength;
      segments.push({
        layerIndex: span.layerIndex,
        layerType: span.layerType,
        byteOffset,
        byteLength: Math.ceil(endBit / 8) - byteOffset,
      });
    }
  }

  return segments;
}

export interface EvaluatedPacketDraft {
  readonly ok: boolean;
  readonly bytes: Uint8Array | null;
  readonly spans: readonly FieldSpan[];
  readonly rows: readonly HexDumpRow[];
  readonly segments: readonly LayerSegmentSummary[];
  readonly resolvedAutoValues?: readonly Readonly<Record<string, number>>[];
  readonly errors: readonly PacketError[];
  readonly warnings: readonly PacketWarning[];
  readonly payloadError?: string;
}

/**
 * レイヤー配列とペイロードパース結果から UI 表示用の状態を組み立てる。
 * ペイロードが不正なときは、空ペイロード前提の誤った AUTO 値や警告を抑止する。
 */
export function evaluatePacketDraft(
  layers: readonly Layer[],
  payloadResult: Result<Uint8Array>,
): EvaluatedPacketDraft {
  if (!payloadResult.ok) {
    // レイヤー側の入力エラー自体は表示できるよう検証のみ行うが、AUTO 値と警告は抑止する
    const layerCheck: BuildPacketResult = buildPacket(layers, new Uint8Array(0));
    return {
      ok: false,
      bytes: null,
      spans: [],
      rows: [],
      segments: [],
      resolvedAutoValues: undefined,
      errors: layerCheck.ok ? [] : layerCheck.errors,
      warnings: [],
      payloadError: payloadResult.error,
    };
  }

  const built = buildPacket(layers, payloadResult.value);
  if (!built.ok) {
    return {
      ok: false,
      bytes: null,
      spans: [],
      rows: [],
      segments: [],
      resolvedAutoValues: undefined,
      errors: built.errors,
      warnings: built.warnings,
      payloadError: undefined,
    };
  }

  return {
    ok: true,
    bytes: built.bytes,
    spans: built.spans,
    rows: buildHexDumpRows(built.bytes, built.spans),
    segments: summarizeLayerSegments(built.spans),
    resolvedAutoValues: built.resolvedAutoValues,
    errors: [],
    warnings: built.warnings,
    payloadError: undefined,
  };
}

/** Formats a byte (0-255) as two 4-bit binary nibbles (e.g., 0x45 -> "0100 0101"). */
export function formatByteBinary(byte: number): string {
  const bits = (byte & 0xff).toString(2).padStart(8, '0');
  return `${bits.slice(0, 4)} ${bits.slice(4)}`;
}

export type HighlightTarget =
  | { readonly kind: 'field'; readonly layerIndex: number; readonly fieldId: string }
  | { readonly kind: 'byte'; readonly byteIndex: number }
  | { readonly kind: 'layer'; readonly layerIndex: number };

/** Returns true if the given FieldSpan matches the active hover/focus target. */
export function doesSpanMatchTarget(
  span: FieldSpan,
  target: HighlightTarget | null,
): boolean {
  if (!target) {
    return false;
  }
  if (target.kind === 'layer') {
    return span.section === 'layer' && span.layerIndex === target.layerIndex;
  }
  if (target.kind === 'field') {
    return span.layerIndex === target.layerIndex && span.fieldId === target.fieldId;
  }
  const byteStartBit = target.byteIndex * 8;
  const byteEndBit = byteStartBit + 8;
  return span.bitOffset < byteEndBit && span.bitOffset + span.bitLength > byteStartBit;
}

/**
 * Resolves which protocol header layer index is currently active for the given highlight target,
 * or null if nothing (or only Payload) is highlighted.
 */
export function resolveHighlightedLayerIndex(
  spans: readonly FieldSpan[],
  target: HighlightTarget | null,
): number | null {
  if (!target) {
    return null;
  }
  if (target.kind === 'layer') {
    const exists = spans.some((s) => s.section === 'layer' && s.layerIndex === target.layerIndex);
    return exists ? target.layerIndex : null;
  }
  if (target.kind === 'field') {
    const match = spans.find(
      (s) =>
        s.section === 'layer' &&
        s.layerIndex === target.layerIndex &&
        s.fieldId === target.fieldId,
    );
    return match ? match.layerIndex : null;
  }
  const match = spans.find((s) => s.section === 'layer' && doesSpanMatchTarget(s, target));
  return match ? match.layerIndex : null;
}

/**
 * Returns the set of packet byte indices that should be highlighted for the given target.
 * Sub-byte fields (e.g., 4-bit IPv4 Version/IHL or 3-bit Flags) highlight every byte
 * containing at least one bit of that field.
 */
export function findHighlightedByteIndices(
  spans: readonly FieldSpan[],
  target: HighlightTarget | null,
): ReadonlySet<number> {
  const indices = new Set<number>();
  if (!target) {
    return indices;
  }
  if (target.kind === 'byte') {
    if (Number.isInteger(target.byteIndex) && target.byteIndex >= 0) {
      indices.add(target.byteIndex);
    }
    return indices;
  }
  for (const span of spans) {
    if (doesSpanMatchTarget(span, target)) {
      const startByte = Math.floor(span.bitOffset / 8);
      const endByte = Math.floor((span.bitOffset + span.bitLength - 1) / 8);
      for (let b = startByte; b <= endByte; b++) {
        indices.add(b);
      }
    }
  }
  return indices;
}

/** Returns true if the given hex dump byte cell should be highlighted. */
export function isByteHighlighted(
  cell: HexByteCell,
  target: HighlightTarget | null,
): boolean {
  if (!target) {
    return false;
  }
  if (target.kind === 'byte') {
    return cell.byteIndex === target.byteIndex;
  }
  return cell.spans.some((s) => doesSpanMatchTarget(s, target));
}

/** Returns true if the given editor field should be highlighted. */
export function isFieldHighlighted(
  layerIndex: number,
  fieldId: string,
  spans: readonly FieldSpan[],
  target: HighlightTarget | null,
): boolean {
  if (!target || target.kind === 'layer') {
    return false;
  }
  if (target.kind === 'field') {
    return target.layerIndex === layerIndex && target.fieldId === fieldId;
  }
  return spans.some(
    (s) =>
      s.layerIndex === layerIndex &&
      s.fieldId === fieldId &&
      doesSpanMatchTarget(s, target),
  );
}

export interface BitDiagramCell {
  readonly span: FieldSpan;
  readonly colStart: number;
  readonly colSpan: number;
  readonly bitLengthInRow: number;
  readonly isContinuation: boolean;
}

export interface BitDiagramRow {
  readonly rowIndex: number;
  readonly bitOffsetInLayer: number;
  readonly totalBitsInRow: number;
  readonly cells: readonly BitDiagramCell[];
}

export interface UnifiedBitDiagramCell extends BitDiagramCell {
  /** True for the very first cell of a protocol header layer */
  readonly isLayerStart: boolean;
  /** True for the very last cell of a protocol header layer */
  readonly isLayerEnd: boolean;
}

export interface UnifiedBitDiagramRow {
  readonly rowIndex: number;
  /** Packet-level bit offset at the start of this 32-bit row (0, 32, 64, ...) */
  readonly bitOffset: number;
  /** Packet-level byte offset at the start of this 32-bit row (0, 4, 8, ...) */
  readonly byteOffset: number;
  readonly totalBitsInRow: number;
  readonly cells: readonly UnifiedBitDiagramCell[];
}

const BITS_PER_DIAGRAM_ROW = 32;

/**
 * Splits a single layer's FieldSpan entries into RFC-style 32-bit-wide rows.
 * Fields spanning a 32-bit boundary (such as 48-bit MAC addresses) are wrapped cleanly
 * onto consecutive rows with `isContinuation: true`.
 */
export function buildBitDiagramRows(
  spans: readonly FieldSpan[],
  layerIndex: number,
): BitDiagramRow[] {
  const layerSpans = spans.filter((s) => s.section === 'layer' && s.layerIndex === layerIndex);
  if (layerSpans.length === 0) {
    return [];
  }

  const baseBitOffset = layerSpans[0].bitOffset;
  const rowMap = new Map<number, BitDiagramCell[]>();

  for (const span of layerSpans) {
    let remaining = span.bitLength;
    let relCursor = span.bitOffset - baseBitOffset;
    let firstPart = true;

    while (remaining > 0) {
      const rowIndex = Math.floor(relCursor / BITS_PER_DIAGRAM_ROW);
      const colStart = relCursor % BITS_PER_DIAGRAM_ROW;
      const spaceInRow = BITS_PER_DIAGRAM_ROW - colStart;
      const take = Math.min(remaining, spaceInRow);

      const cells = rowMap.get(rowIndex) ?? [];
      cells.push({
        span,
        colStart,
        colSpan: take,
        bitLengthInRow: take,
        isContinuation: !firstPart,
      });
      rowMap.set(rowIndex, cells);

      relCursor += take;
      remaining -= take;
      firstPart = false;
    }
  }

  const rows: BitDiagramRow[] = [];
  const sortedIndices = [...rowMap.keys()].sort((a, b) => a - b);
  for (const rowIndex of sortedIndices) {
    const cells = rowMap.get(rowIndex)!;
    const totalBitsInRow = cells.reduce((acc, c) => acc + c.bitLengthInRow, 0);
    rows.push({
      rowIndex,
      bitOffsetInLayer: rowIndex * BITS_PER_DIAGRAM_ROW,
      totalBitsInRow,
      cells,
    });
  }

  return rows;
}

/**
 * Splits ALL protocol header layers (`section === 'layer'`) continuously into a single
 * unified 32-bit-wide diagram in wire order, marking header start/end boundaries so the UI
 * can color-code and emphasize each header's exact bit range.
 */
export function buildUnifiedBitDiagramRows(
  spans: readonly FieldSpan[],
): UnifiedBitDiagramRow[] {
  const headerSpans = spans.filter((s) => s.section === 'layer');
  if (headerSpans.length === 0) {
    return [];
  }

  const layerRanges = new Map<number, { startBit: number; endBit: number }>();
  for (const span of headerSpans) {
    const spanEnd = span.bitOffset + span.bitLength;
    const existing = layerRanges.get(span.layerIndex);
    if (!existing) {
      layerRanges.set(span.layerIndex, { startBit: span.bitOffset, endBit: spanEnd });
    } else {
      if (span.bitOffset < existing.startBit) existing.startBit = span.bitOffset;
      if (spanEnd > existing.endBit) existing.endBit = spanEnd;
    }
  }

  const rowMap = new Map<number, UnifiedBitDiagramCell[]>();

  for (const span of headerSpans) {
    const range = layerRanges.get(span.layerIndex)!;
    let remaining = span.bitLength;
    let cursor = span.bitOffset;
    let firstPart = true;

    while (remaining > 0) {
      const rowIndex = Math.floor(cursor / BITS_PER_DIAGRAM_ROW);
      const colStart = cursor % BITS_PER_DIAGRAM_ROW;
      const spaceInRow = BITS_PER_DIAGRAM_ROW - colStart;
      const take = Math.min(remaining, spaceInRow);

      const cells = rowMap.get(rowIndex) ?? [];
      cells.push({
        span,
        colStart,
        colSpan: take,
        bitLengthInRow: take,
        isContinuation: !firstPart,
        isLayerStart: cursor === range.startBit,
        isLayerEnd: cursor + take === range.endBit,
      });
      rowMap.set(rowIndex, cells);

      cursor += take;
      remaining -= take;
      firstPart = false;
    }
  }

  const rows: UnifiedBitDiagramRow[] = [];
  const sortedIndices = [...rowMap.keys()].sort((a, b) => a - b);
  for (const rowIndex of sortedIndices) {
    const cells = rowMap.get(rowIndex)!;
    const totalBitsInRow = cells.reduce((acc, c) => acc + c.bitLengthInRow, 0);
    rows.push({
      rowIndex,
      bitOffset: rowIndex * BITS_PER_DIAGRAM_ROW,
      byteOffset: rowIndex * (BITS_PER_DIAGRAM_ROW / 8),
      totalBitsInRow,
      cells,
    });
  }

  return rows;
}
