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
/** EtherType for ARP (RFC 826) */
export const ETHERTYPE_ARP = 0x0806;
/** EtherType for IPv6 (RFC 2464) */
export const ETHERTYPE_IPV6 = 0x86dd;
/** TPID for IEEE 802.1Q C-tag VLAN */
export const ETHERTYPE_VLAN = 0x8100;
/** TPID for IEEE 802.1ad S-tag QinQ (Provider Bridges, IEEE 802.1Q §9.4) */
export const ETHERTYPE_QINQ = 0x88a8;
/** Legacy non-standard QinQ TPID (decoded for compatibility, not auto-generated) */
export const ETHERTYPE_QINQ_LEGACY = 0x9100;

export const ETHERNET_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'dstMac', label: 'Destination MAC', bitOffset: 0, bitLength: 48 },
  { fieldId: 'srcMac', label: 'Source MAC', bitOffset: 48, bitLength: 48 },
  { fieldId: 'etherType', label: 'EtherType', bitOffset: 96, bitLength: 16 },
];

export interface EncodeEthernetContext {
  readonly layerIndex: number;
  readonly upperLayerType: LayerType | null;
  /** Layer immediately following `upperLayerType` (used to distinguish single 802.1Q vs. 802.1ad QinQ) */
  readonly upperNextLayerType?: LayerType | null;
  readonly upperBytesLength: number;
}

export function ethernetEtherTypeForUpperLayers(
  upperLayerType: LayerType | null,
  upperNextLayerType: LayerType | null = null,
): number | null {
  if (upperLayerType === 'ipv4') return ETHERTYPE_IPV4;
  if (upperLayerType === 'ipv6') return ETHERTYPE_IPV6;
  if (upperLayerType === 'arp') return ETHERTYPE_ARP;
  if (upperLayerType === 'vlan') {
    return upperNextLayerType === 'vlan' ? ETHERTYPE_QINQ : ETHERTYPE_VLAN;
  }
  return null;
}

function upperLayerNameForEtherType(
  upperLayerType: LayerType | null,
  upperNextLayerType: LayerType | null = null,
): string {
  if (upperLayerType === 'arp') return 'ARP';
  if (upperLayerType === 'ipv6') return 'IPv6';
  if (upperLayerType === 'vlan') {
    return upperNextLayerType === 'vlan' ? '802.1ad QinQ S-tag' : '802.1Q VLAN';
  }
  return 'IPv4';
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

  const upperNext = ctx.upperNextLayerType ?? null;
  const inferredEtherType = ethernetEtherTypeForUpperLayers(ctx.upperLayerType, upperNext);
  const autoEtherType = inferredEtherType ?? ETHERTYPE_IPV4;
  let etherTypeValue = autoEtherType;

  if (layer.etherType.mode === 'manual') {
    const rangeErr = validateUintRange(layer.etherType.value, 0xffff, 'EtherType');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'etherType', message: rangeErr });
    } else {
      etherTypeValue = layer.etherType.value;
      if (inferredEtherType !== null && etherTypeValue !== inferredEtherType) {
        const expectedHex = `0x${inferredEtherType.toString(16).padStart(4, '0')}`;
        const upperName = upperLayerNameForEtherType(ctx.upperLayerType, upperNext);
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'etherType',
          message: `Using manual EtherType 0x${etherTypeValue.toString(16).padStart(4, '0')} (standard ${upperName} value is ${expectedHex}).`,
        });
      }
    }
  } else if (inferredEtherType === null) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'etherType',
      message: 'Upper layer is not IPv4, IPv6, ARP, or VLAN; defaulting EtherType to 0x0800.',
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
