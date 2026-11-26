import { concatBytes, writeUint16BE, writeUint32BE } from '../bytes';
import { ipv6PseudoHeaderChecksum } from '../checksum';
import type {
  ICMPv6Layer,
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';
import type { IPPseudoContext } from './udp';

/** Base ICMPv6 header length (8 bytes, RFC 4443 §2.1) */
export const ICMPV6_HEADER_LENGTH = 8;
/** IANA Next Header / Protocol number for IPv6-ICMP (RFC 4443 §2.1) */
export const IP_PROTOCOL_ICMPV6 = 58;
/** Packet Too Big (RFC 4443 §3.2) */
export const ICMPV6_TYPE_PACKET_TOO_BIG = 2;
/** Parameter Problem (RFC 4443 §3.4) */
export const ICMPV6_TYPE_PARAMETER_PROBLEM = 4;
/** Echo Request (RFC 4443 §4.1) */
export const ICMPV6_TYPE_ECHO_REQUEST = 128;
/** Echo Reply (RFC 4443 §4.2) */
export const ICMPV6_TYPE_ECHO_REPLY = 129;

export interface EncodeICMPv6Context {
  readonly layerIndex: number;
  readonly upperBytes: Uint8Array;
  /** Immediately preceding IP layer state used for mandatory IPv6 pseudo-header checksum */
  readonly ip: IPPseudoContext;
}

/**
 * Returns the RFC 4443 field label for the 32-bit body header in non-Echo ICMPv6 messages:
 * MTU for Type 2 (Packet Too Big, §3.2), Pointer for Type 4 (Parameter Problem, §3.4),
 * and Unused otherwise.
 */
export function getICMPv6RawFieldLabel(icmpType: number): string {
  if (icmpType === ICMPV6_TYPE_PACKET_TOO_BIG) {
    return 'MTU';
  }
  if (icmpType === ICMPV6_TYPE_PARAMETER_PROBLEM) {
    return 'Pointer';
  }
  return 'Unused';
}

/**
 * Returns contiguous 64-bit field spans for either the Echo (ID + Seq) or Raw (32-bit) ICMPv6 header.
 */
export function getICMPv6FieldSpans(layer: ICMPv6Layer): readonly RelativeFieldSpan[] {
  const base: RelativeFieldSpan[] = [
    { fieldId: 'icmpType', label: 'Type', bitOffset: 0, bitLength: 8 },
    { fieldId: 'code', label: 'Code', bitOffset: 8, bitLength: 8 },
    { fieldId: 'checksum', label: 'Checksum', bitOffset: 16, bitLength: 16 },
  ];

  if (layer.rest.kind === 'echo') {
    base.push(
      { fieldId: 'identifier', label: 'Identifier', bitOffset: 32, bitLength: 16 },
      { fieldId: 'sequence', label: 'Sequence Number', bitOffset: 48, bitLength: 16 },
    );
  } else {
    base.push({
      fieldId: 'restValue',
      label: getICMPv6RawFieldLabel(layer.icmpType),
      bitOffset: 32,
      bitLength: 32,
    });
  }

  return base;
}

/**
 * Encodes an 8-byte ICMPv6 header (RFC 4443 §2.1) with mandatory IPv6 pseudo-header checksum
 * (RFC 4443 §2.3 / RFC 8200 §8.1).
 */
export function encodeICMPv6(layer: ICMPv6Layer, ctx: EncodeICMPv6Context): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const typeErr = validateUintRange(layer.icmpType, 0xff, 'ICMPv6 Type');
  if (typeErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'icmpType', message: typeErr });
  }

  const codeErr = validateUintRange(layer.code, 0xff, 'ICMPv6 Code');
  if (codeErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'code', message: codeErr });
  }

  if (layer.rest.kind === 'echo') {
    const idErr = validateUintRange(layer.rest.identifier, 0xffff, 'Identifier');
    if (idErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'identifier', message: idErr });
    }
    const seqErr = validateUintRange(layer.rest.sequence, 0xffff, 'Sequence Number');
    if (seqErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'sequence', message: seqErr });
    }
  } else {
    const rawLabel = getICMPv6RawFieldLabel(layer.icmpType);
    const valErr = validateUintRange(layer.rest.value, 0xffffffff, rawLabel);
    if (valErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'restValue', message: valErr });
    }
  }

  if (layer.checksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.checksum.value, 0xffff, 'ICMPv6 Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumErr });
    }
  }

  const isDirectlyOverIPv4 =
    (ctx.ip.status === 'valid' && ctx.ip.version === 4) ||
    (ctx.ip.status === 'invalid' && ctx.ip.version === 4);

  if (isDirectlyOverIPv4) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message:
        'ICMPv6 sits directly above IPv4; use ICMP (RFC 792) for IPv4 packets.',
    });
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(ICMPV6_HEADER_LENGTH);
  header[0] = layer.icmpType;
  header[1] = layer.code;
  header[2] = 0;
  header[3] = 0;

  if (layer.rest.kind === 'echo') {
    writeUint16BE(header, 4, layer.rest.identifier);
    writeUint16BE(header, 6, layer.rest.sequence);
  } else {
    writeUint32BE(header, 4, layer.rest.value);
  }

  let autoChecksum = 0;
  const hasValidIPv6 = ctx.ip.status === 'valid' && ctx.ip.version === 6;
  const hasInvalidIPv6 = ctx.ip.status === 'invalid' && ctx.ip.version === 6;

  if (hasValidIPv6) {
    const segment = concatBytes(header, ctx.upperBytes);
    const csumResult = ipv6PseudoHeaderChecksum({
      srcIp: ctx.ip.srcIp,
      dstIp: ctx.ip.dstIp,
      nextHeader: IP_PROTOCOL_ICMPV6,
      segment,
    });
    if (!csumResult.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumResult.error });
      return { ok: false, errors, warnings };
    }
    autoChecksum = csumResult.value;
  } else if (!hasInvalidIPv6 && layer.checksum.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message:
        'No underlying IPv6 layer for pseudo-header; setting ICMPv6 Checksum to 0x0000 (RFC 4443 §2.3).',
    });
  }

  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 2, checksumValue);

  if (layer.checksum.mode === 'manual' && hasValidIPv6 && checksumValue !== autoChecksum) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: `Using manual ICMPv6 Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
    });
  }

  return {
    ok: true,
    bytes: header,
    spans: getICMPv6FieldSpans(layer),
    warnings,
    resolvedAutoValues: {
      checksum: autoChecksum,
    },
  };
}
