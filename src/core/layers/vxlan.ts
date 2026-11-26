import type {
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
  VXLANLayer,
} from './types';
import { validateUintRange } from './types';

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

export type VXLANUnderlyingUDPContext =
  | { readonly status: 'valid'; readonly srcPort: number; readonly dstPort: number }
  | { readonly status: 'invalid' }
  | { readonly status: 'absent' };

export interface EncodeVXLANContext {
  readonly layerIndex: number;
  /** Immediately preceding UDP layer state for RFC 7348 §5 transport / port 4789 hints */
  readonly udp: VXLANUnderlyingUDPContext;
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
