import { concatBytes, writeUint16BE } from '../bytes';
import { ipv4PseudoHeaderChecksum, ipv6PseudoHeaderChecksum } from '../checksum';
import { IP_PROTOCOL_UDP } from './ipv4';
import type {
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
  UDPLayer,
} from './types';
import { validateUintRange } from './types';

/** UDP header length (8 bytes, RFC 768) */
export const UDP_HEADER_LENGTH = 8;
export const UDP_MAX_LENGTH = 0xffff;

export const UDP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'srcPort', label: 'Source Port', bitOffset: 0, bitLength: 16 },
  { fieldId: 'dstPort', label: 'Destination Port', bitOffset: 16, bitLength: 16 },
  { fieldId: 'length', label: 'Length', bitOffset: 32, bitLength: 16 },
  { fieldId: 'checksum', label: 'Checksum', bitOffset: 48, bitLength: 16 },
];

export type IPPseudoContext =
  | {
      readonly status: 'valid';
      readonly version: 4 | 6;
      readonly srcIp: Uint8Array;
      readonly dstIp: Uint8Array;
    }
  | { readonly status: 'invalid'; readonly version?: 4 | 6 }
  | { readonly status: 'absent' };

export interface EncodeUDPContext {
  readonly layerIndex: number;
  readonly upperLayerType?: LayerType | null;
  readonly upperBytes: Uint8Array;
  /** Immediately preceding IPv4 or IPv6 layer state used for pseudo-header checksum calculation */
  readonly ip: IPPseudoContext;
}

/**
 * Encodes an 8-byte UDP header (RFC 768 / RFC 8200 §8.1).
 * Converts a computed checksum of 0x0000 to 0xffff per RFC 768 and RFC 8200 §8.1.
 */
export function encodeUDP(layer: UDPLayer, ctx: EncodeUDPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const srcPortErr = validateUintRange(layer.srcPort, 0xffff, 'Source Port');
  if (srcPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcPort', message: srcPortErr });
  }

  const dstPortErr = validateUintRange(layer.dstPort, 0xffff, 'Destination Port');
  if (dstPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstPort', message: dstPortErr });
  }

  const actualLength = UDP_HEADER_LENGTH + ctx.upperBytes.length;
  if (actualLength > UDP_MAX_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'length',
      message: `UDP length exceeds the 65535-byte limit (got ${actualLength} bytes, RFC 768).`,
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
          message: `Manual UDP Length (${lengthValue}) is smaller than the 8-byte minimum (RFC 768).`,
        });
      } else if (actualLength <= UDP_MAX_LENGTH && lengthValue !== actualLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `Using manual UDP Length ${lengthValue} (actual length is ${actualLength} bytes).`,
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
  if (ctx.ip.status === 'valid') {
    const segment = concatBytes(header, ctx.upperBytes);
    const csumResult =
      ctx.ip.version === 4
        ? ipv4PseudoHeaderChecksum({
            srcIp: ctx.ip.srcIp,
            dstIp: ctx.ip.dstIp,
            protocol: IP_PROTOCOL_UDP,
            segment,
          })
        : ipv6PseudoHeaderChecksum({
            srcIp: ctx.ip.srcIp,
            dstIp: ctx.ip.dstIp,
            nextHeader: IP_PROTOCOL_UDP,
            segment,
          });
    if (!csumResult.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumResult.error });
      return { ok: false, errors, warnings };
    }
    // RFC 768 / RFC 8200 §8.1: transmit all-ones (0xffff) when computed checksum is zero
    autoChecksum = csumResult.value === 0 ? 0xffff : csumResult.value;
  } else if (ctx.ip.status === 'absent' && layer.checksum.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: 'No underlying IPv4 or IPv6 layer for pseudo-header; setting UDP Checksum to 0x0000 (unused).',
    });
  }

  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 6, checksumValue);

  if (layer.checksum.mode === 'manual' && ctx.ip.status === 'valid') {
    if (checksumValue === 0) {
      if (ctx.ip.version === 6) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'checksum',
          message:
            'UDP Checksum is mandatory over IPv6; packets with a 0x0000 checksum must be discarded by receivers (RFC 8200 §8.1).',
        });
      } else if (ctx.upperLayerType !== 'vxlan') {
        // RFC 7348 §5: VXLAN over IPv4 SHOULD transmit outer UDP checksum as 0x0000 (and MAY be non-zero); do not warn on either choice.
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'checksum',
          message: 'UDP Checksum is set to 0x0000 (checksum disabled / unused per RFC 768).',
        });
      }
    } else if (checksumValue !== autoChecksum) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'checksum',
        message: `Using manual UDP Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
      });
    }
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
