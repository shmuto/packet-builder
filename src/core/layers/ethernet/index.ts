import { formatMac, parseMac, readUint16BE, writeUint16BE } from '../../bytes';
import { err, ok, type Result } from '../../result';
import type {
  DecodeLayerContext,
  FieldDoc,
  LayerDefinition,
  ProtocolTables,
} from '../definition';
import {
  expectString,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import { getDefaultProtocolTables } from '../registry';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type EthernetLayer,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

/** Ethernet II header length (14 bytes) */
export const ETHERNET_HEADER_LENGTH = 14;
/** IEEE 802.3 minimum Ethernet frame size excluding 4-byte FCS (60 bytes) */
export const ETHERNET_MIN_FRAME_LENGTH = 60;
/** Transparent Ethernet Bridging (GRETAP) GRE Protocol Type (RFC 1701 / IANA IEEE 802 Numbers) */
export const GRE_PROTOCOL_TEB = 0x6558;

export const ETHERNET_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'dstMac', label: 'Destination MAC', bitOffset: 0, bitLength: 48 },
  { fieldId: 'srcMac', label: 'Source MAC', bitOffset: 48, bitLength: 48 },
  { fieldId: 'etherType', label: 'EtherType', bitOffset: 96, bitLength: 16 },
];

export const ETHERNET_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  dstMac: {
    summary:
      '48-bit hardware address of the intended recipient on the local link. Use ff:ff:ff:ff:ff:ff for broadcast frames such as ARP requests.',
    reference: 'IEEE 802.3 §3.2.4',
  },
  srcMac: {
    summary:
      '48-bit hardware address of the interface transmitting the Ethernet frame on the local link.',
    reference: 'IEEE 802.3 §3.2.5',
  },
  etherType: {
    summary:
      '16-bit identifier declaring which protocol or VLAN TPID follows the Ethernet header. Common values are 0x0800 (IPv4), 0x86dd (IPv6), 0x0806 (ARP), 0x8100 (802.1Q C-tag), and 0x88a8 (802.1ad S-tag).',
    reference: 'IEEE 802.3 §3.2.6 / IEEE 802.1Q §9.5',
  },
};

export interface EncodeEthernetContext {
  readonly layerIndex: number;
  readonly upperLayerType: string | null;
  /** Layer immediately following `upperLayerType` (used to distinguish single 802.1Q vs. 802.1ad QinQ) */
  readonly upperNextLayerType?: string | null;
  readonly upperBytesLength: number;
  readonly tables?: ProtocolTables;
}

export function createDefaultEthernet(): EthernetLayer {
  return {
    type: 'ethernet',
    dstMac: '00:11:22:33:44:55',
    srcMac: '66:77:88:99:aa:bb',
    etherType: autoValue(),
  };
}

export function ethernetEtherTypeForUpperLayers(
  upperLayerType: string | null,
  upperNextLayerType: string | null = null,
  tables: ProtocolTables = getDefaultProtocolTables(),
): number | null {
  return tables.resolveEthernetEtherType(upperLayerType, upperNextLayerType)?.value ?? null;
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
  const tables = ctx.tables ?? getDefaultProtocolTables();

  const dstMacResult = parseMac(layer.dstMac);
  if (!dstMacResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstMac', message: dstMacResult.error });
  }

  const srcMacResult = parseMac(layer.srcMac);
  if (!srcMacResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcMac', message: srcMacResult.error });
  }

  const upperNext = ctx.upperNextLayerType ?? null;
  const resolved = tables.resolveEthernetEtherType(ctx.upperLayerType, upperNext);
  const inferredEtherType = resolved?.value ?? null;
  const autoEtherType = inferredEtherType ?? tables.defaultEtherType;
  let etherTypeValue = autoEtherType;

  if (layer.etherType.mode === 'manual') {
    const rangeErr = validateUintRange(layer.etherType.value, 0xffff, 'EtherType');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'etherType', message: rangeErr });
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

function decodeEthernetFrame(
  bytes: Uint8Array,
  offset: number,
  ctx: DecodeLayerContext,
  tunnelDepth: number,
) {
  const dstMac = formatMac(bytes.subarray(offset, offset + 6));
  const srcMac = formatMac(bytes.subarray(offset + 6, offset + 12));
  const etherType = readUint16BE(bytes, offset + 12);

  const upper = ctx.decodeByEtherType(bytes, offset + ETHERNET_HEADER_LENGTH, etherType, {
    vlanDepth: 0,
    tunnelDepth,
    parentKind: 'link',
  });

  const expected = ctx.tables.resolveEthernetEtherType(
    upper.layers[0]?.type ?? null,
    upper.layers[1]?.type ?? null,
  );
  const ethLayer: EthernetLayer = {
    type: 'ethernet',
    dstMac,
    srcMac,
    etherType:
      expected !== null && etherType === expected.value
        ? autoValue()
        : manualValue(etherType),
  };

  return {
    layers: [ethLayer, ...upper.layers],
    payload: upper.payload,
  };
}

function validateEthernetPermalink(
  raw: Record<string, unknown>,
  ctx: string,
): Result<EthernetLayer> {
  const checked = validateExactKeys(raw, ['type', 'dstMac', 'srcMac', 'etherType'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const dstMac = expectString(obj, 'dstMac', ctx);
  if (!dstMac.ok) return dstMac;
  const srcMac = expectString(obj, 'srcMac', ctx);
  if (!srcMac.ok) return srcMac;
  const etherType = validateAutoOrManualNumber(obj.etherType, `${ctx}.etherType`);
  if (!etherType.ok) return etherType;
  return ok({
    type: 'ethernet',
    dstMac: dstMac.value,
    srcMac: srcMac.value,
    etherType: etherType.value,
  });
}

export const ethernetDefinition: LayerDefinition<EthernetLayer, 'ethernet'> = {
  type: 'ethernet',
  minHeaderLength: ETHERNET_HEADER_LENGTH,
  createDefault: createDefaultEthernet,
  headerLength: () => ETHERNET_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeEthernet(layer, {
      layerIndex: ctx.layerIndex,
      upperLayerType: ctx.upperLayerType,
      upperNextLayerType: ctx.upperNextLayerType,
      upperBytesLength: ctx.upperBytesLength,
      tables: ctx.tables,
    }),
  decodeStart(bytes, ctx) {
    if (bytes.length < ETHERNET_HEADER_LENGTH) {
      return err(
        `Packet is too short for an Ethernet II header (need at least ${ETHERNET_HEADER_LENGTH} bytes, got ${bytes.length}).`,
      );
    }
    return ok(decodeEthernetFrame(bytes, 0, ctx, 0));
  },
  decode(bytes, offset, ctx) {
    const remaining = bytes.length - offset;
    if (remaining < ETHERNET_HEADER_LENGTH) {
      if (ctx.carrier === 'greProtocol') {
        const protoHex = (ctx.dispatchedValue ?? GRE_PROTOCOL_TEB)
          .toString(16)
          .padStart(4, '0');
        ctx.notes.push(
          `Ethernet II frame after GRE (0x${protoHex}) is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
        );
      } else if (remaining > 0) {
        ctx.notes.push(
          `Inner Ethernet II frame after ${ctx.enclosingLabel} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
        );
      }
      return null;
    }
    return decodeEthernetFrame(bytes, offset, ctx, ctx.tunnelDepth);
  },
  validatePermalink: validateEthernetPermalink,
  fieldDocs: ETHERNET_FIELD_DOCS,
  protocols: {
    greProtocolType: GRE_PROTOCOL_TEB,
    greLabel: 'Ethernet II (Transparent Ethernet Bridging)',
    isLinkFrame: true,
  },
};
