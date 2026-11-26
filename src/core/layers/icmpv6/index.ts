import {
  concatBytes,
  readUint16BE,
  readUint32BE,
  writeUint16BE,
  writeUint32BE,
} from '../../bytes';
import { ipv6PseudoHeaderChecksum } from '../../checksum';
import { err, ok, type Result } from '../../result';
import { computePseudoChecksum } from '../decodeHelpers';
import type { FieldDoc, IPPseudoContext, LayerDefinition } from '../definition';
import {
  expectNumber,
  isPlainObject,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type ICMPv6Layer,
  type ICMPv6Rest,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

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

export const ICMPV6_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  icmpType: {
    summary:
      '8-bit message category: 0-127 are error messages (such as 2 = Packet Too Big, 4 = Parameter Problem) and 128-255 are informational messages (128 = Echo Request, 129 = Echo Reply).',
    reference: 'RFC 4443 §2.1',
  },
  code: {
    summary:
      '8-bit subtype refining the ICMPv6 Type (for example, 0 for Echo Request/Reply and Packet Too Big, or 0-2 for Parameter Problem).',
    reference: 'RFC 4443 §2.1',
  },
  checksum: {
    summary:
      "16-bit mandatory one's-complement checksum covering the 40-byte IPv6 pseudo-header (Next Header 58), the ICMPv6 header, and the message payload.",
    reference: 'RFC 4443 §2.3 / RFC 8200 §8.1',
  },
  identifier: {
    summary:
      '16-bit identifier chosen by the sender to match Echo Replies back to the originating IPv6 ping session.',
    reference: 'RFC 4443 §4.1 / §4.2',
  },
  sequence: {
    summary:
      '16-bit counter incremented for each Echo Request sent in a session to order replies and detect packet loss.',
    reference: 'RFC 4443 §4.1 / §4.2',
  },
  restValue: {
    summary:
      '32-bit type-specific header field: carries the next-hop link MTU for Packet Too Big (Type 2), the byte offset Pointer for Parameter Problem (Type 4), or Unused zero bits for other messages.',
    reference: 'RFC 4443 §2.1 / §3.2 / §3.4',
  },
};

export interface EncodeICMPv6Context {
  readonly layerIndex: number;
  readonly upperBytes: Uint8Array;
  /** Immediately preceding IP layer state used for mandatory IPv6 pseudo-header checksum */
  readonly ip: IPPseudoContext;
}

/** Creates a default ICMPv6 Echo Request header (Type 128, Code 0, RFC 4443 §4.1). */
export function createDefaultICMPv6(): ICMPv6Layer {
  return {
    type: 'icmpv6',
    icmpType: 128,
    code: 0,
    checksum: autoValue(),
    rest: {
      kind: 'echo',
      identifier: 1,
      sequence: 1,
    },
  };
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
      message: 'ICMPv6 sits directly above IPv4; use ICMP (RFC 792) for IPv4 packets.',
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

function validateICMPv6Rest(raw: unknown, context: string): Result<ICMPv6Rest> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const kind = raw.kind;
  if (kind === 'echo') {
    const checked = validateExactKeys(raw, ['kind', 'identifier', 'sequence'], context);
    if (!checked.ok) return checked;
    const identifier = expectNumber(checked.value, 'identifier', context);
    if (!identifier.ok) return identifier;
    const sequence = expectNumber(checked.value, 'sequence', context);
    if (!sequence.ok) return sequence;
    return ok({ kind: 'echo', identifier: identifier.value, sequence: sequence.value });
  }
  if (kind === 'raw') {
    const checked = validateExactKeys(raw, ['kind', 'value'], context);
    if (!checked.ok) return checked;
    const value = expectNumber(checked.value, 'value', context);
    if (!value.ok) return value;
    return ok({ kind: 'raw', value: value.value });
  }
  return err(`${context}.kind must be "echo" or "raw".`);
}

function validateICMPv6Permalink(
  raw: Record<string, unknown>,
  ctx: string,
): Result<ICMPv6Layer> {
  const checked = validateExactKeys(raw, ['type', 'icmpType', 'code', 'checksum', 'rest'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const icmpType = expectNumber(obj, 'icmpType', ctx);
  if (!icmpType.ok) return icmpType;
  const code = expectNumber(obj, 'code', ctx);
  if (!code.ok) return code;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const rest = validateICMPv6Rest(obj.rest, `${ctx}.rest`);
  if (!rest.ok) return rest;
  return ok({
    type: 'icmpv6',
    icmpType: icmpType.value,
    code: code.value,
    checksum: checksum.value,
    rest: rest.value,
  });
}

export const icmpv6Definition: LayerDefinition<ICMPv6Layer, 'icmpv6'> = {
  type: 'icmpv6',
  minHeaderLength: ICMPV6_HEADER_LENGTH,
  createDefault: createDefaultICMPv6,
  headerLength: () => ICMPV6_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeICMPv6(layer, {
      layerIndex: ctx.layerIndex,
      upperBytes: ctx.upperBytes,
      ip: ctx.ip,
    }),
  decode(bytes, offset, ctx) {
    const icmpType = bytes[offset];
    const code = bytes[offset + 1];
    const checksum = readUint16BE(bytes, offset + 2);

    // Type 128 (Echo Request) and Type 129 (Echo Reply) always decode to the Echo variant
    // (even if originally constructed using the Raw 32-bit variant); the wire bytes are identical.
    const isEcho =
      icmpType === ICMPV6_TYPE_ECHO_REQUEST || icmpType === ICMPV6_TYPE_ECHO_REPLY;
    const rest = isEcho
      ? ({
          kind: 'echo',
          identifier: readUint16BE(bytes, offset + 4),
          sequence: readUint16BE(bytes, offset + 6),
        } as const)
      : ({
          kind: 'raw',
          value: readUint32BE(bytes, offset + 4),
        } as const);

    const segmentCopy = new Uint8Array(bytes.subarray(offset));
    segmentCopy[2] = 0;
    segmentCopy[3] = 0;
    const expectedChecksum = ctx.ip
      ? (() => {
          const csumRes = computePseudoChecksum(ctx.ip, IP_PROTOCOL_ICMPV6, segmentCopy);
          return csumRes.ok ? csumRes.value : null;
        })()
      : null;

    const layer: ICMPv6Layer = {
      type: 'icmpv6',
      icmpType,
      code,
      checksum:
        expectedChecksum !== null && checksum === expectedChecksum
          ? autoValue()
          : manualValue(checksum),
      rest,
    };

    return {
      layers: [layer],
      payload: bytes.slice(offset + ICMPV6_HEADER_LENGTH),
    };
  },
  validatePermalink: validateICMPv6Permalink,
  fieldDocs: ICMPV6_FIELD_DOCS,
  protocols: {
    ipv6NextHeader: IP_PROTOCOL_ICMPV6,
  },
};
