import { concatBytes, writeUint16BE } from '../bytes';
import { internetChecksum } from '../checksum';
import type {
  ICMPLayer,
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** ICMP base header length (8 bytes, RFC 792) */
export const ICMP_HEADER_LENGTH = 8;

export const ICMP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'icmpType', label: 'Type', bitOffset: 0, bitLength: 8 },
  { fieldId: 'code', label: 'Code', bitOffset: 8, bitLength: 8 },
  { fieldId: 'checksum', label: 'Checksum', bitOffset: 16, bitLength: 16 },
  { fieldId: 'identifier', label: 'Identifier', bitOffset: 32, bitLength: 16 },
  { fieldId: 'sequenceNumber', label: 'Sequence Number', bitOffset: 48, bitLength: 16 },
];

export interface EncodeICMPContext {
  readonly layerIndex: number;
  readonly upperBytes: Uint8Array;
}

/**
 * Encodes an 8-byte ICMP header (RFC 792, e.g., Echo Request / Reply).
 */
export function encodeICMP(layer: ICMPLayer, ctx: EncodeICMPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const typeErr = validateUintRange(layer.icmpType, 0xff, 'ICMP Type');
  if (typeErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'icmpType', message: typeErr });
  }

  const codeErr = validateUintRange(layer.code, 0xff, 'ICMP Code');
  if (codeErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'code', message: codeErr });
  }

  const idErr = validateUintRange(layer.identifier, 0xffff, 'Identifier');
  if (idErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'identifier', message: idErr });
  }

  const seqErr = validateUintRange(layer.sequenceNumber, 0xffff, 'Sequence Number');
  if (seqErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'sequenceNumber', message: seqErr });
  }

  if (layer.checksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.checksum.value, 0xffff, 'ICMP Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumErr });
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(ICMP_HEADER_LENGTH);
  header[0] = layer.icmpType;
  header[1] = layer.code;
  header[2] = 0;
  header[3] = 0;
  writeUint16BE(header, 4, layer.identifier);
  writeUint16BE(header, 6, layer.sequenceNumber);

  // RFC 792: checksum covers the entire ICMP header + payload
  const message = concatBytes(header, ctx.upperBytes);
  const autoChecksum = internetChecksum(message);
  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 2, checksumValue);

  if (layer.checksum.mode === 'manual' && checksumValue !== autoChecksum) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: `Using manual ICMP Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
    });
  }

  return {
    ok: true,
    bytes: header,
    spans: ICMP_FIELD_SPANS,
    warnings,
    resolvedAutoValues: { checksum: autoChecksum },
  };
}
