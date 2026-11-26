import { writeUint16BE } from '../bytes';
import {
  ETHERTYPE_ARP,
  ETHERTYPE_IPV4,
  ETHERTYPE_IPV6,
  ETHERTYPE_VLAN,
} from './ethernet';
import type {
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
  VLANLayer,
} from './types';
import { validateUintRange } from './types';

/**
 * Wire-format model note (IEEE 802.1Q §9.3 / §9.6):
 * On the wire, an 802.1Q tag is `[TPID (16b) | TCI (16b)]` inserted ahead of the inner EtherType.
 * Because the preceding layer (`Ethernet II` or an outer `VLAN` tag) already owns the 16-bit
 * EtherType field at the TPID byte offset, each `VLANLayer` encodes the 4 bytes
 * `[TCI (16b) | Next EtherType / inner TPID (16b)]`:
 *   - PCP (3 bits) + DEI (1 bit) + VID (12 bits) = 16-bit Tag Control Information (TCI)
 *   - EtherType / TPID (16 bits) declaring the protocol or inner C-tag that follows.
 */
export const VLAN_HEADER_LENGTH = 4;
export const VLAN_MAX_PCP = 7;
export const VLAN_MAX_VID = 4095;

export const VLAN_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'pcp', label: 'PCP', bitOffset: 0, bitLength: 3 },
  { fieldId: 'dei', label: 'DEI', bitOffset: 3, bitLength: 1 },
  { fieldId: 'vid', label: 'VID', bitOffset: 4, bitLength: 12 },
  { fieldId: 'etherType', label: 'EtherType', bitOffset: 16, bitLength: 16 },
];

export interface EncodeVLANContext {
  readonly layerIndex: number;
  readonly upperLayerType: LayerType | null;
}

/**
 * Returns the standard EtherType / inner TPID for the layer directly above a VLAN tag.
 * Per IEEE 802.1ad (incorporated into IEEE 802.1Q), a tag directly inside an outer S-tag is a
 * C-tag (`0x8100`).
 */
export function vlanInnerEtherTypeForUpperLayer(upperLayerType: LayerType | null): number | null {
  switch (upperLayerType) {
    case 'ipv4':
      return ETHERTYPE_IPV4;
    case 'arp':
      return ETHERTYPE_ARP;
    case 'ipv6':
      return ETHERTYPE_IPV6;
    case 'vlan':
      return ETHERTYPE_VLAN;
    default:
      return null;
  }
}

function upperLayerNameForVLAN(upperLayerType: LayerType | null): string {
  switch (upperLayerType) {
    case 'arp':
      return 'ARP';
    case 'ipv6':
      return 'IPv6';
    case 'vlan':
      return '802.1Q C-tag VLAN';
    default:
      return 'IPv4';
  }
}

/**
 * Encodes a 4-byte IEEE 802.1Q / 802.1ad VLAN tag body (`TCI (16b) + inner EtherType (16b)`).
 */
export function encodeVLAN(layer: VLANLayer, ctx: EncodeVLANContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const pcpErr = validateUintRange(layer.pcp, VLAN_MAX_PCP, 'PCP');
  if (pcpErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'pcp', message: pcpErr });
  }

  const vidErr = validateUintRange(layer.vid, VLAN_MAX_VID, 'VID');
  if (vidErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'vid', message: vidErr });
  } else if (layer.vid === 0) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'vid',
      message:
        'VID 0 indicates a priority-tagged frame carrying no VLAN ID (IEEE 802.1Q §9.6).',
    });
  } else if (layer.vid === VLAN_MAX_VID) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'vid',
      message:
        'VID 4095 (0xfff) is reserved for implementation use and must not be transmitted on the wire (IEEE 802.1Q §9.6).',
    });
  }

  const inferredEtherType = vlanInnerEtherTypeForUpperLayer(ctx.upperLayerType);
  const autoEtherType = inferredEtherType ?? ETHERTYPE_IPV4;
  let etherTypeValue = autoEtherType;

  if (layer.etherType.mode === 'manual') {
    const etErr = validateUintRange(layer.etherType.value, 0xffff, 'EtherType');
    if (etErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'etherType', message: etErr });
    } else {
      etherTypeValue = layer.etherType.value;
      if (inferredEtherType !== null && etherTypeValue !== inferredEtherType) {
        const expectedHex = `0x${inferredEtherType.toString(16).padStart(4, '0')}`;
        const upperName = upperLayerNameForVLAN(ctx.upperLayerType);
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

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const tci = ((layer.pcp & 0x7) << 13) | ((layer.dei ? 1 : 0) << 12) | (layer.vid & 0xfff);
  const header = new Uint8Array(VLAN_HEADER_LENGTH);
  writeUint16BE(header, 0, tci);
  writeUint16BE(header, 2, etherTypeValue);

  return {
    ok: true,
    bytes: header,
    spans: VLAN_FIELD_SPANS,
    warnings,
    resolvedAutoValues: { etherType: autoEtherType },
  };
}
