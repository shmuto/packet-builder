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

/** Ethernet II header length (14 bytes) */
export const ETHERNET_HEADER_LENGTH = 14;
/** IEEE 802.3 minimum Ethernet frame size excluding 4-byte FCS (60 bytes) */
export const ETHERNET_MIN_FRAME_LENGTH = 60;
/** EtherType for IPv4 (RFC 894) */
export const ETHERTYPE_IPV4 = 0x0800;

export const ETHERNET_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'dstMac', label: 'Destination MAC', bitOffset: 0, bitLength: 48 },
  { fieldId: 'srcMac', label: 'Source MAC', bitOffset: 48, bitLength: 48 },
  { fieldId: 'etherType', label: 'EtherType', bitOffset: 96, bitLength: 16 },
];

export interface EncodeEthernetContext {
  readonly layerIndex: number;
  readonly upperLayerType: LayerType | null;
  readonly upperBytesLength: number;
}

/**
 * Encodes an Ethernet II header (14 bytes, RFC 894 / IEEE 802.3).
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
          message: `Using manual EtherType 0x${etherTypeValue.toString(16).padStart(4, '0')} (standard IPv4 value is 0x0800, RFC 894).`,
        });
      }
    }
  } else if (ctx.upperLayerType !== 'ipv4') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'etherType',
      message: 'Upper layer is not IPv4; defaulting EtherType to 0x0800.',
    });
  }

  if (errors.length > 0 || !dstMacResult.ok || !srcMacResult.ok) {
    return { ok: false, errors, warnings };
  }

  const totalFrameLength = ETHERNET_HEADER_LENGTH + ctx.upperBytesLength;
  if (totalFrameLength < ETHERNET_MIN_FRAME_LENGTH) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: `Frame length is ${totalFrameLength} bytes. IEEE 802.3 requires at least 60 bytes excluding FCS (NICs pad shorter frames with 0x00).`,
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
