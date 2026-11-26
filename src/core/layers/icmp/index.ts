import { concatBytes, readUint16BE, writeUint16BE } from '../../bytes';
import { internetChecksum } from '../../checksum';
import { ok, type Result } from '../../result';
import type { FieldDoc, LayerDefinition } from '../definition';
import {
  expectNumber,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type ICMPLayer,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

/** ICMP base header length (8 bytes, RFC 792) */
export const ICMP_HEADER_LENGTH = 8;
/** IANA IPv4 Protocol number for ICMP (RFC 792) */
export const IP_PROTOCOL_ICMP = 1;

export const ICMP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'icmpType', label: 'Type', bitOffset: 0, bitLength: 8 },
  { fieldId: 'code', label: 'Code', bitOffset: 8, bitLength: 8 },
  { fieldId: 'checksum', label: 'Checksum', bitOffset: 16, bitLength: 16 },
  { fieldId: 'identifier', label: 'Identifier', bitOffset: 32, bitLength: 16 },
  { fieldId: 'sequenceNumber', label: 'Sequence Number', bitOffset: 48, bitLength: 16 },
];

export const ICMP_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  icmpType: {
    summary:
      '8-bit category of the ICMP control or diagnostic message. Common values are 8 (Echo Request / ping) and 0 (Echo Reply).',
    reference: 'RFC 792 "Echo or Echo Reply Message"',
  },
  code: {
    summary:
      '8-bit subtype giving extra context for the ICMP Type. Always 0 for Echo Request and Echo Reply.',
    reference: 'RFC 792 "Echo or Echo Reply Message"',
  },
  checksum: {
    summary:
      "16-bit one's-complement checksum calculated over the entire ICMP header and payload to detect corruption.",
    reference: 'RFC 792 "Echo or Echo Reply Message"',
  },
  identifier: {
    summary:
      '16-bit value chosen by the sender (often a process ID) to match Echo Replies back to the originating ping session.',
    reference: 'RFC 792 "Echo or Echo Reply Message"',
  },
  sequenceNumber: {
    summary:
      '16-bit counter incremented for each Echo Request sent in a session so replies can be ordered and packet loss detected.',
    reference: 'RFC 792 "Echo or Echo Reply Message"',
  },
};

export interface EncodeICMPContext {
  readonly layerIndex: number;
  readonly upperBytes: Uint8Array;
}

export function createDefaultICMP(): ICMPLayer {
  return {
    type: 'icmp',
    icmpType: 8,
    code: 0,
    checksum: autoValue(),
    identifier: 1,
    sequenceNumber: 1,
  };
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

function validateICMPPermalink(raw: Record<string, unknown>, ctx: string): Result<ICMPLayer> {
  const checked = validateExactKeys(
    raw,
    ['type', 'icmpType', 'code', 'checksum', 'identifier', 'sequenceNumber'],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const icmpType = expectNumber(obj, 'icmpType', ctx);
  if (!icmpType.ok) return icmpType;
  const code = expectNumber(obj, 'code', ctx);
  if (!code.ok) return code;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const identifier = expectNumber(obj, 'identifier', ctx);
  if (!identifier.ok) return identifier;
  const sequenceNumber = expectNumber(obj, 'sequenceNumber', ctx);
  if (!sequenceNumber.ok) return sequenceNumber;
  return ok({
    type: 'icmp',
    icmpType: icmpType.value,
    code: code.value,
    checksum: checksum.value,
    identifier: identifier.value,
    sequenceNumber: sequenceNumber.value,
  });
}

export const icmpDefinition: LayerDefinition<ICMPLayer, 'icmp'> = {
  type: 'icmp',
  minHeaderLength: ICMP_HEADER_LENGTH,
  createDefault: createDefaultICMP,
  headerLength: () => ICMP_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeICMP(layer, {
      layerIndex: ctx.layerIndex,
      upperBytes: ctx.upperBytes,
    }),
  decode(bytes, offset) {
    const icmpType = bytes[offset];
    const code = bytes[offset + 1];
    const checksum = readUint16BE(bytes, offset + 2);
    const identifier = readUint16BE(bytes, offset + 4);
    const sequenceNumber = readUint16BE(bytes, offset + 6);

    const segmentCopy = new Uint8Array(bytes.subarray(offset));
    segmentCopy[2] = 0;
    segmentCopy[3] = 0;
    const computed = internetChecksum(segmentCopy);

    const layer: ICMPLayer = {
      type: 'icmp',
      icmpType,
      code,
      checksum: checksum === computed ? autoValue() : manualValue(checksum),
      identifier,
      sequenceNumber,
    };

    return {
      layers: [layer],
      payload: bytes.slice(offset + ICMP_HEADER_LENGTH),
    };
  },
  validatePermalink: validateICMPPermalink,
  fieldDocs: ICMP_FIELD_DOCS,
  protocols: {
    ipv4Protocol: IP_PROTOCOL_ICMP,
    ipv6MismatchWarning:
      'ICMPv4 sits directly above IPv6; use ICMPv6 (Next Header 58, RFC 4443) for IPv6 packets.',
  },
};
