import { ok, type Result } from '../../result';
import {
  MAX_IP_LAYERS,
  type FieldDoc,
  type LayerDefinition,
  type UDPTransportContext,
} from '../definition';
import {
  expectNumber,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
  type VXLANLayer,
} from '../types';

/** Fixed VXLAN header length (8 bytes, RFC 7348 §5) */
export const VXLAN_HEADER_LENGTH = 8;
/** IANA-assigned UDP destination port for VXLAN (RFC 7348 §5) */
export const VXLAN_PORT = 4789;
/** VXLAN I-flag bit (bit 4 in network bit order = 0x08): MUST be 1 for a valid VNI (RFC 7348 §5) */
export const VXLAN_FLAG_I = 0x08;
/** Maximum 24-bit VXLAN Network Identifier (2^24 - 1 = 16,777,215) */
export const VXLAN_MAX_VNI = 0xffffff;
/** Maximum 24-bit Reserved field value */
export const VXLAN_MAX_RESERVED1 = 0xffffff;
/** Maximum 8-bit Reserved field value */
export const VXLAN_MAX_RESERVED2 = 0xff;

export const VXLAN_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'flags', label: 'Flags (I)', bitOffset: 0, bitLength: 8 },
  { fieldId: 'reserved1', label: 'Reserved (24b)', bitOffset: 8, bitLength: 24 },
  { fieldId: 'vni', label: 'VNI', bitOffset: 32, bitLength: 24 },
  { fieldId: 'reserved2', label: 'Reserved (8b)', bitOffset: 56, bitLength: 8 },
];

export const VXLAN_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  flags: {
    summary:
      '8-bit VXLAN Flags (RRRRIRRR). Bit 4 (I-flag, 0x08) must be set to 1 for a valid VNI, and all other 7 bits are reserved (0). Per RFC 7348 §5, the outer UDP checksum SHOULD be transmitted as zero over IPv4, and a non-zero checksum MAY be used.',
    reference: 'RFC 7348 §5',
  },
  reserved1: {
    summary:
      '24-bit reserved field following Flags; must be set to 0 on transmission and ignored on receipt.',
    reference: 'RFC 7348 §5',
  },
  vni: {
    summary:
      '24-bit VXLAN Network Identifier (0-16,777,215) isolating virtual Layer 2 overlay segments across an IP/UDP (port 4789) underlay.',
    reference: 'RFC 7348 §5',
  },
  reserved2: {
    summary:
      '8-bit reserved field following the 24-bit VNI; must be set to 0 on transmission and ignored on receipt.',
    reference: 'RFC 7348 §5',
  },
};

export type VXLANUnderlyingUDPContext = UDPTransportContext;

export interface EncodeVXLANContext {
  readonly layerIndex: number;
  /** Immediately preceding UDP layer state for RFC 7348 §5 transport / port 4789 hints */
  readonly udp: VXLANUnderlyingUDPContext;
}

/** Creates a default VXLAN header (I-flag auto 0x08, VNI 100, reserved fields 0, RFC 7348 §5). */
export function createDefaultVXLAN(): VXLANLayer {
  return {
    type: 'vxlan',
    flags: autoValue(),
    vni: 100,
    reserved1: 0,
    reserved2: 0,
  };
}

/**
 * Encodes an 8-byte Virtual eXtensible Local Area Network (VXLAN) header (RFC 7348 §5).
 */
export function encodeVXLAN(layer: VXLANLayer, ctx: EncodeVXLANContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  if (ctx.udp.status === 'absent') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: 'No underlying UDP layer; VXLAN runs over UDP destination port 4789 (RFC 7348 §5).',
    });
  } else if (ctx.udp.status === 'valid' && ctx.udp.dstPort !== VXLAN_PORT) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: `Underlying UDP destination port is ${ctx.udp.dstPort}; IANA-assigned VXLAN UDP destination port is ${VXLAN_PORT} (RFC 7348 §5).`,
    });
  }

  let flagsValue = VXLAN_FLAG_I;
  if (layer.flags.mode === 'manual') {
    const flagsErr = validateUintRange(layer.flags.value, 0xff, 'VXLAN Flags');
    if (flagsErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'flags', message: flagsErr });
    } else {
      flagsValue = layer.flags.value;
      if ((flagsValue & VXLAN_FLAG_I) === 0) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'flags',
          message:
            'VXLAN I-flag (0x08) is not set; RFC 7348 §5 requires the I-flag to be 1 for a valid VNI.',
        });
      }
      if ((flagsValue & ~VXLAN_FLAG_I) !== 0) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'flags',
          message: `VXLAN Flags 0x${flagsValue.toString(16).padStart(2, '0')} has non-zero reserved bit(s); RFC 7348 §5 reserves all bits except the I-flag (0x08) as zero.`,
        });
      }
    }
  }

  const res1Err = validateUintRange(layer.reserved1, VXLAN_MAX_RESERVED1, 'Reserved (24-bit)');
  if (res1Err !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'reserved1', message: res1Err });
  } else if (layer.reserved1 !== 0) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'reserved1',
      message:
        'VXLAN 24-bit Reserved field is non-zero; RFC 7348 §5 requires reserved fields to be set to zero on transmission.',
    });
  }

  const vniErr = validateUintRange(layer.vni, VXLAN_MAX_VNI, 'VNI');
  if (vniErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'vni', message: vniErr });
  }

  const res2Err = validateUintRange(layer.reserved2, VXLAN_MAX_RESERVED2, 'Reserved (8-bit)');
  if (res2Err !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'reserved2', message: res2Err });
  } else if (layer.reserved2 !== 0) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'reserved2',
      message:
        'VXLAN 8-bit Reserved field is non-zero; RFC 7348 §5 requires reserved fields to be set to zero on transmission.',
    });
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(VXLAN_HEADER_LENGTH);
  header[0] = flagsValue & 0xff;
  header[1] = (layer.reserved1 >>> 16) & 0xff;
  header[2] = (layer.reserved1 >>> 8) & 0xff;
  header[3] = layer.reserved1 & 0xff;
  header[4] = (layer.vni >>> 16) & 0xff;
  header[5] = (layer.vni >>> 8) & 0xff;
  header[6] = layer.vni & 0xff;
  header[7] = layer.reserved2 & 0xff;

  return {
    ok: true,
    bytes: header,
    spans: VXLAN_FIELD_SPANS,
    warnings,
    resolvedAutoValues: { flags: VXLAN_FLAG_I },
  };
}

function validateVXLANPermalink(raw: Record<string, unknown>, ctx: string): Result<VXLANLayer> {
  const checked = validateExactKeys(raw, ['type', 'flags', 'vni', 'reserved1', 'reserved2'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const flags = validateAutoOrManualNumber(obj.flags, `${ctx}.flags`);
  if (!flags.ok) return flags;
  const vni = expectNumber(obj, 'vni', ctx);
  if (!vni.ok) return vni;
  const reserved1 = expectNumber(obj, 'reserved1', ctx);
  if (!reserved1.ok) return reserved1;
  const reserved2 = expectNumber(obj, 'reserved2', ctx);
  if (!reserved2.ok) return reserved2;

  return ok({
    type: 'vxlan',
    flags: flags.value,
    vni: vni.value,
    reserved1: reserved1.value,
    reserved2: reserved2.value,
  });
}

export const vxlanDefinition: LayerDefinition<VXLANLayer, 'vxlan'> = {
  type: 'vxlan',
  minHeaderLength: VXLAN_HEADER_LENGTH,
  createDefault: createDefaultVXLAN,
  headerLength: () => VXLAN_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeVXLAN(layer, {
      layerIndex: ctx.layerIndex,
      udp: ctx.udp,
    }),
  decode(bytes, offset, ctx) {
    const remaining = bytes.length - offset;
    if (remaining < VXLAN_HEADER_LENGTH) {
      if (remaining > 0) {
        ctx.notes.push(
          `UDP payload on port ${VXLAN_PORT} is too short for a VXLAN header (${remaining} bytes, need at least ${VXLAN_HEADER_LENGTH}); remaining bytes kept as Payload.`,
        );
      }
      return null;
    }

    const flags = bytes[offset];
    if ((flags & VXLAN_FLAG_I) === 0) {
      ctx.notes.push(
        `UDP payload on port ${VXLAN_PORT} does not have the VXLAN I-flag (0x08) set (Flags 0x${flags.toString(16).padStart(2, '0')}); per RFC 7348 §5 remaining bytes are kept as Payload.`,
      );
      return null;
    }

    const reserved1 =
      (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const vni =
      (bytes[offset + 4] << 16) | (bytes[offset + 5] << 8) | bytes[offset + 6];
    const reserved2 = bytes[offset + 7];

    const vxlanLayer: VXLANLayer = {
      type: 'vxlan',
      flags: flags === VXLAN_FLAG_I ? autoValue() : manualValue(flags),
      vni,
      reserved1,
      reserved2,
    };

    const innerOffset = offset + VXLAN_HEADER_LENGTH;
    if (ctx.tunnelDepth + 1 >= MAX_IP_LAYERS) {
      ctx.notes.push(
        `VXLAN tunnel depth limit (${MAX_IP_LAYERS}) exceeded; remaining bytes kept as Payload.`,
      );
      return { layers: [vxlanLayer], payload: bytes.slice(innerOffset) };
    }

    const inner = ctx.decodeLinkFrame(bytes, innerOffset, ctx.tunnelDepth + 1, 'VXLAN');
    return {
      layers: [vxlanLayer, ...inner.layers],
      payload: inner.payload,
    };
  },
  validatePermalink: validateVXLANPermalink,
  fieldDocs: VXLAN_FIELD_DOCS,
  protocols: {
    udpPort: VXLAN_PORT,
    allowsZeroUdpChecksumOverIPv4: true,
  },
};
