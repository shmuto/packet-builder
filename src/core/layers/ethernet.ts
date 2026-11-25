import { parseMac, writeUint16BE } from '../bytes';
import type {
  EthernetLayer,
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** Ethernet II ヘッダ長（14 バイト） */
export const ETHERNET_HEADER_LENGTH = 14;
/** IEEE 802.3 最小フレーム長（FCS 除く 60 バイト） */
export const ETHERNET_MIN_FRAME_LENGTH = 60;
/** IPv4 の EtherType（RFC 894） */
export const ETHERTYPE_IPV4 = 0x0800;

export const ETHERNET_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'dstMac', label: '宛先 MAC アドレス', bitOffset: 0, bitLength: 48 },
  { fieldId: 'srcMac', label: '送信元 MAC アドレス', bitOffset: 48, bitLength: 48 },
  { fieldId: 'etherType', label: 'EtherType', bitOffset: 96, bitLength: 16 },
];

export interface EncodeEthernetContext {
  readonly layerIndex: number;
  readonly upperLayerType: LayerType | null;
  readonly upperBytesLength: number;
}

/**
 * Ethernet II ヘッダ（14 バイト）をエンコードする（RFC 894 / IEEE 802.3）。
 */
export function encodeEthernet(
  layer: EthernetLayer,
  ctx: EncodeEthernetContext,
): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const dstMacResult = parseMac(layer.dstMac);
  if (!dstMacResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstMac', message: dstMacResult.error });
  }

  const srcMacResult = parseMac(layer.srcMac);
  if (!srcMacResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcMac', message: srcMacResult.error });
  }

  // 自動計算する EtherType（直上が IPv4 のときは RFC 894 に従い 0x0800）
  const autoEtherType = ETHERTYPE_IPV4;
  let etherTypeValue = autoEtherType;

  if (layer.etherType.mode === 'manual') {
    const rangeErr = validateUintRange(layer.etherType.value, 0xffff, 'EtherType');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'etherType', message: rangeErr });
    } else {
      etherTypeValue = layer.etherType.value;
      if (ctx.upperLayerType === 'ipv4' && etherTypeValue !== autoEtherType) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'etherType',
          message: `EtherType に手動値 0x${etherTypeValue.toString(16).padStart(4, '0')} を使用しています（IPv4 の標準値は 0x0800）。`,
        });
      }
    }
  } else if (ctx.upperLayerType !== 'ipv4') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'etherType',
      message: '直上のレイヤーが IPv4 ではないため、EtherType に仮値 0x0800 を設定しています。',
    });
  }

  if (errors.length > 0 || !dstMacResult.ok || !srcMacResult.ok) {
    return { ok: false, errors, warnings };
  }

  const totalFrameLength = ETHERNET_HEADER_LENGTH + ctx.upperBytesLength;
  if (totalFrameLength < ETHERNET_MIN_FRAME_LENGTH) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: `フレーム長が ${totalFrameLength} バイトです。IEEE 802.3 では FCS を除き最小 60 バイト必要なため、実ネットワークでは 0x00 でパディングされます。`,
    });
  }

  const header = new Uint8Array(ETHERNET_HEADER_LENGTH);
  header.set(dstMacResult.value, 0);
  header.set(srcMacResult.value, 6);
  writeUint16BE(header, 12, etherTypeValue);

  return {
    ok: true,
    bytes: header,
    spans: ETHERNET_FIELD_SPANS,
    warnings,
    resolvedAutoValues: { etherType: autoEtherType },
  };
}
