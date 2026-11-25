import { concatBytes, writeUint16BE } from '../bytes';
import { ipv4PseudoHeaderChecksum } from '../checksum';
import { IP_PROTOCOL_UDP } from './ipv4';
import type {
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
  UDPLayer,
} from './types';
import { validateUintRange } from './types';

/** UDP ヘッダ長（8 バイト、RFC 768） */
export const UDP_HEADER_LENGTH = 8;
export const UDP_MAX_LENGTH = 0xffff;

export const UDP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'srcPort', label: '送信元ポート', bitOffset: 0, bitLength: 16 },
  { fieldId: 'dstPort', label: '宛先ポート', bitOffset: 16, bitLength: 16 },
  { fieldId: 'length', label: 'Length', bitOffset: 32, bitLength: 16 },
  { fieldId: 'checksum', label: 'Checksum', bitOffset: 48, bitLength: 16 },
];

export type IPv4PseudoContext =
  | { readonly status: 'valid'; readonly srcIp: Uint8Array; readonly dstIp: Uint8Array }
  | { readonly status: 'invalid' }
  | { readonly status: 'absent' };

export interface EncodeUDPContext {
  readonly layerIndex: number;
  readonly upperBytes: Uint8Array;
  /** 下位 IPv4 レイヤーの状態（擬似ヘッダ計算用） */
  readonly ipv4: IPv4PseudoContext;
}

/**
 * UDP ヘッダ（8 バイト）をエンコードする（RFC 768）。
 * チェックサム計算結果が 0x0000 になる場合は RFC 768 に従い 0xffff を格納する。
 */
export function encodeUDP(layer: UDPLayer, ctx: EncodeUDPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const srcPortErr = validateUintRange(layer.srcPort, 0xffff, '送信元ポート');
  if (srcPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcPort', message: srcPortErr });
  }

  const dstPortErr = validateUintRange(layer.dstPort, 0xffff, '宛先ポート');
  if (dstPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstPort', message: dstPortErr });
  }

  const actualLength = UDP_HEADER_LENGTH + ctx.upperBytes.length;
  if (actualLength > UDP_MAX_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'length',
      message: `UDP の長さが上限 65535 バイトを超えています（現在 ${actualLength} バイト）。`,
    });
  }

  let lengthValue = actualLength;
  if (layer.length.mode === 'manual') {
    const lenErr = validateUintRange(layer.length.value, 0xffff, 'UDP Length');
    if (lenErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'length', message: lenErr });
    } else {
      lengthValue = layer.length.value;
      if (lengthValue < UDP_HEADER_LENGTH) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `UDP Length（${lengthValue}）が最小値 8 バイト未満です（RFC 768）。`,
        });
      } else if (actualLength <= UDP_MAX_LENGTH && lengthValue !== actualLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `UDP Length に手動値 ${lengthValue} を使用しています（実際の長さは ${actualLength} バイト）。`,
        });
      }
    }
  }

  if (layer.checksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.checksum.value, 0xffff, 'UDP Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumErr });
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(UDP_HEADER_LENGTH);
  writeUint16BE(header, 0, layer.srcPort);
  writeUint16BE(header, 2, layer.dstPort);
  writeUint16BE(header, 4, lengthValue);
  header[6] = 0;
  header[7] = 0;

  let autoChecksum = 0;
  if (ctx.ipv4.status === 'valid') {
    const segment = concatBytes(header, ctx.upperBytes);
    const csumResult = ipv4PseudoHeaderChecksum({
      srcIp: ctx.ipv4.srcIp,
      dstIp: ctx.ipv4.dstIp,
      protocol: IP_PROTOCOL_UDP,
      segment,
    });
    if (!csumResult.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumResult.error });
      return { ok: false, errors, warnings };
    }
    // RFC 768: 計算結果がすべて 0 のときは、チェックサム未使用（0x0000）と区別するため 0xffff を送出する
    autoChecksum = csumResult.value === 0 ? 0xffff : csumResult.value;
  } else if (ctx.ipv4.status === 'absent' && layer.checksum.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: '下位に IPv4 レイヤーがないため擬似ヘッダを作成できず、UDP Checksum を 0x0000（未使用）に設定しました。',
    });
  }

  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 6, checksumValue);

  if (
    layer.checksum.mode === 'manual' &&
    ctx.ipv4.status === 'valid' &&
    checksumValue !== autoChecksum
  ) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: `UDP Checksum に手動値 0x${checksumValue.toString(16).padStart(4, '0')} を使用しています（正しい計算値は 0x${autoChecksum.toString(16).padStart(4, '0')}）。`,
    });
  }

  return {
    ok: true,
    bytes: header,
    spans: UDP_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      length: actualLength,
      checksum: autoChecksum,
    },
  };
}
