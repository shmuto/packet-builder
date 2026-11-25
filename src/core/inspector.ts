import type { FieldSpan, LayerType } from './layers/types';

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
