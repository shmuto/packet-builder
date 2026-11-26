import { readUint16BE, writeUint16BE } from '../../bytes';
import { ok, type Result } from '../../result';
import {
  MAX_VLAN_TAGS,
  type FieldDoc,
  type LayerDefinition,
  type ProtocolTables,
} from '../definition';
import {
  expectBoolean,
  expectNumber,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import { getDefaultProtocolTables } from '../registry';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
  type VLANLayer,
} from '../types';

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
/** TPID for IEEE 802.1Q C-tag VLAN */
export const ETHERTYPE_VLAN = 0x8100;
/** TPID for IEEE 802.1ad S-tag QinQ (Provider Bridges, IEEE 802.1Q §9.4) */
export const ETHERTYPE_QINQ = 0x88a8;
/** Legacy non-standard QinQ TPID (decoded for compatibility, not auto-generated) */
export const ETHERTYPE_QINQ_LEGACY = 0x9100;

export const VLAN_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'pcp', label: 'PCP', bitOffset: 0, bitLength: 3 },
  { fieldId: 'dei', label: 'DEI', bitOffset: 3, bitLength: 1 },
  { fieldId: 'vid', label: 'VID', bitOffset: 4, bitLength: 12 },
  { fieldId: 'etherType', label: 'EtherType', bitOffset: 16, bitLength: 16 },
];

export const VLAN_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  pcp: {
    summary:
      '3-bit Priority Code Point (0-7) specifying the Layer 2 class-of-service priority for this tagged frame. On the wire, the 16-bit TPID (0x8100 or 0x88a8) sits in the preceding Ethernet or outer VLAN EtherType field.',
    reference: 'IEEE 802.1Q §9.6',
  },
  dei: {
    summary:
      '1-bit Drop Eligible Indicator (formerly CFI) signaling whether this frame may be dropped first during network congestion (0 = not drop-eligible, 1 = drop-eligible).',
    reference: 'IEEE 802.1Q §9.6',
  },
  vid: {
    summary:
      '12-bit VLAN Identifier (0-4095) assigning the frame to a virtual LAN. Values 1-4094 are normal VLANs; 0 denotes a priority-tagged frame and 4095 (0xfff) is reserved.',
    reference: 'IEEE 802.1Q §9.6',
  },
  etherType: {
    summary:
      '16-bit EtherType (or inner TPID in QinQ) declaring the protocol that follows this 4-byte VLAN tag body (TCI + EtherType): 0x0800 (IPv4), 0x86dd (IPv6), 0x0806 (ARP), or 0x8100 (inner C-tag).',
    reference: 'IEEE 802.1Q §9.5 / IEEE 802.3 §3.2.6',
  },
};

export interface EncodeVLANContext {
  readonly layerIndex: number;
  readonly upperLayerType: string | null;
  readonly tables?: ProtocolTables;
}

/** Creates a default IEEE 802.1Q VLAN tag (PCP 0, DEI 0, VID 100). */
export function createDefaultVLAN(): VLANLayer {
  return {
    type: 'vlan',
    pcp: 0,
    dei: false,
    vid: 100,
    etherType: autoValue(),
  };
}

/**
 * Returns the standard EtherType / inner TPID for the layer directly above a VLAN tag.
 */
export function vlanInnerEtherTypeForUpperLayer(
  upperLayerType: string | null,
  tables: ProtocolTables = getDefaultProtocolTables(),
): number | null {
  return tables.resolveVlanEtherType(upperLayerType)?.value ?? null;
}

/**
 * Encodes a 4-byte IEEE 802.1Q / 802.1ad VLAN tag body (`TCI (16b) + inner EtherType (16b)`).
 */
export function encodeVLAN(layer: VLANLayer, ctx: EncodeVLANContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];
  const tables = ctx.tables ?? getDefaultProtocolTables();

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

  const resolved = tables.resolveVlanEtherType(ctx.upperLayerType);
  const inferredEtherType = resolved?.value ?? null;
  const autoEtherType = inferredEtherType ?? tables.defaultEtherType;
  let etherTypeValue = autoEtherType;

  if (layer.etherType.mode === 'manual') {
    const etErr = validateUintRange(layer.etherType.value, 0xffff, 'EtherType');
    if (etErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'etherType', message: etErr });
    } else {
      etherTypeValue = layer.etherType.value;
      if (resolved !== null && etherTypeValue !== resolved.value) {
        const expectedHex = `0x${resolved.value.toString(16).padStart(4, '0')}`;
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'etherType',
          message: `Using manual EtherType 0x${etherTypeValue.toString(16).padStart(4, '0')} (standard ${resolved.label} value is ${expectedHex}).`,
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

function validateVLANPermalink(
  raw: Record<string, unknown>,
  ctx: string,
): Result<VLANLayer> {
  const checked = validateExactKeys(raw, ['type', 'pcp', 'dei', 'vid', 'etherType'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const pcp = expectNumber(obj, 'pcp', ctx);
  if (!pcp.ok) return pcp;
  const dei = expectBoolean(obj, 'dei', ctx);
  if (!dei.ok) return dei;
  const vid = expectNumber(obj, 'vid', ctx);
  if (!vid.ok) return vid;
  const etherType = validateAutoOrManualNumber(obj.etherType, `${ctx}.etherType`);
  if (!etherType.ok) return etherType;
  return ok({
    type: 'vlan',
    pcp: pcp.value,
    dei: dei.value,
    vid: vid.value,
    etherType: etherType.value,
  });
}

export const vlanDefinition: LayerDefinition<VLANLayer, 'vlan'> = {
  type: 'vlan',
  minHeaderLength: VLAN_HEADER_LENGTH,
  createDefault: createDefaultVLAN,
  headerLength: () => VLAN_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeVLAN(layer, {
      layerIndex: ctx.layerIndex,
      upperLayerType: ctx.upperLayerType,
      tables: ctx.tables,
    }),
  decode(bytes, offset, ctx) {
    if (ctx.vlanDepth >= MAX_VLAN_TAGS) {
      ctx.notes.push(
        `VLAN tag depth limit (${MAX_VLAN_TAGS} tags) exceeded; remaining bytes kept as Payload.`,
      );
      return null;
    }
    const remaining = bytes.length - offset;
    const tpid = ctx.dispatchedValue ?? ETHERTYPE_VLAN;
    if (remaining < VLAN_HEADER_LENGTH) {
      ctx.notes.push(
        `VLAN tag header (TPID 0x${tpid.toString(16).padStart(4, '0')}) is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return null;
    }

    const tci = readUint16BE(bytes, offset);
    const pcp = (tci >>> 13) & 0x7;
    const dei = ((tci >>> 12) & 0x1) !== 0;
    const vid = tci & 0xfff;
    const innerEtherType = readUint16BE(bytes, offset + 2);

    const upper = ctx.decodeByEtherType(bytes, offset + VLAN_HEADER_LENGTH, innerEtherType, {
      vlanDepth: ctx.vlanDepth + 1,
      tunnelDepth: ctx.tunnelDepth,
      parentKind: ctx.etherTypeParentKind,
    });

    const expectedInner = ctx.tables.resolveVlanEtherType(upper.layers[0]?.type ?? null);
    const vlanLayer: VLANLayer = {
      type: 'vlan',
      pcp,
      dei,
      vid,
      etherType:
        expectedInner !== null && innerEtherType === expectedInner.value
          ? autoValue()
          : manualValue(innerEtherType),
    };

    return {
      layers: [vlanLayer, ...upper.layers],
      payload: upper.payload,
    };
  },
  validatePermalink: validateVLANPermalink,
  fieldDocs: VLAN_FIELD_DOCS,
  protocols: {
    etherType: ETHERTYPE_VLAN,
    stackedEtherType: ETHERTYPE_QINQ,
    decodeEtherTypes: [ETHERTYPE_QINQ_LEGACY],
    etherTypeLabel: '802.1Q VLAN',
    stackedEtherTypeLabel: '802.1ad QinQ S-tag',
    vlanInnerEtherTypeLabel: '802.1Q C-tag VLAN',
    greLabel: '802.1Q VLAN',
  },
};
