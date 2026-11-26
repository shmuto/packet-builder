import {
  formatIPv4,
  parseHexBytes,
  parseIPv4,
  readUint16BE,
  writeUint16BE,
} from '../../bytes';
import { err, ok, type Result } from '../../result';
import type {
  FieldDoc,
  LayerDefinition,
  TCPTransportContext,
} from '../definition';
import {
  expectNumber,
  expectString,
  validateAutoOrManualNumber,
  validateAutoOrManualString,
  validateExactKeys,
} from '../permalinkHelpers';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type BGPLayer,
  type BGPMessageType,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

/** BGP-4 common header length (19 bytes: 16B Marker + 2B Length + 1B Type, RFC 4271 §4.1) */
export const BGP_COMMON_HEADER_LENGTH = 19;
export const BGP_OPEN_HEADER_LENGTH = 29;
export const BGP_UPDATE_HEADER_LENGTH = 23;
export const BGP_NOTIFICATION_HEADER_LENGTH = 21;
export const BGP_KEEPALIVE_HEADER_LENGTH = 19;

export const BGP_PORT = 179;
export const BGP_VERSION_4 = 4;
export const BGP_RFC4271_MAX_LENGTH = 4096;
export const BGP_TYPE_OPEN = 1;
export const BGP_TYPE_UPDATE = 2;
export const BGP_TYPE_NOTIFICATION = 3;
export const BGP_TYPE_KEEPALIVE = 4;

export const BGP_DEFAULT_MARKER_HEX = 'ff'.repeat(16);

const MIN_VALID_TCP_DATA_OFFSET = 5;

const BGP_TYPE_NAMES: Readonly<Record<BGPMessageType, string>> = {
  1: 'OPEN',
  2: 'UPDATE',
  3: 'NOTIFICATION',
  4: 'KEEPALIVE',
};

const COMMON_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'marker', label: 'Marker', bitOffset: 0, bitLength: 128 },
  { fieldId: 'length', label: 'Length', bitOffset: 128, bitLength: 16 },
  { fieldId: 'bgpType', label: 'Type', bitOffset: 144, bitLength: 8 },
];

export const BGP_OPEN_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  ...COMMON_SPANS,
  { fieldId: 'version', label: 'Version', bitOffset: 152, bitLength: 8 },
  { fieldId: 'myAs', label: 'My AS', bitOffset: 160, bitLength: 16 },
  { fieldId: 'holdTime', label: 'Hold Time', bitOffset: 176, bitLength: 16 },
  { fieldId: 'bgpIdentifier', label: 'BGP Identifier', bitOffset: 192, bitLength: 32 },
  { fieldId: 'optParamLength', label: 'Opt. Parm Len', bitOffset: 224, bitLength: 8 },
];

export const BGP_UPDATE_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  ...COMMON_SPANS,
  { fieldId: 'withdrawnRoutesLength', label: 'Withdrawn Routes Len', bitOffset: 152, bitLength: 16 },
  { fieldId: 'totalPathAttrLength', label: 'Total Path Attr Len', bitOffset: 168, bitLength: 16 },
];

export const BGP_NOTIFICATION_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  ...COMMON_SPANS,
  { fieldId: 'errorCode', label: 'Error Code', bitOffset: 152, bitLength: 8 },
  { fieldId: 'errorSubcode', label: 'Error Subcode', bitOffset: 160, bitLength: 8 },
];

export const BGP_KEEPALIVE_FIELD_SPANS: readonly RelativeFieldSpan[] = COMMON_SPANS;

export const BGP_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  marker: {
    summary:
      '16-byte synchronization field that must be set to all ones (0xff × 16) in BGP-4 for message framing compatibility.',
    reference: 'RFC 4271 §4.1',
  },
  length: {
    summary:
      'Total length of the BGP message in bytes, including the 19-byte common header. Standard BGP-4 allows 19 to 4,096 bytes, or up to 65,535 bytes when both peers negotiate RFC 8654 Extended Messages.',
    reference: 'RFC 4271 §4.1 / RFC 8654 §3',
  },
  bgpType: {
    summary:
      '1-byte code identifying the BGP message type: 1 (OPEN), 2 (UPDATE), 3 (NOTIFICATION), or 4 (KEEPALIVE).',
    reference: 'RFC 4271 §4.1',
  },
  version: {
    summary:
      '1-byte protocol version advertised during session setup. Always 4 for BGP-4.',
    reference: 'RFC 4271 §4.2',
  },
  myAs: {
    summary:
      '16-bit Autonomous System Number (ASN) of the BGP speaker sending the OPEN message (use 23456 when carrying a 4-byte ASN in capabilities).',
    reference: 'RFC 4271 §4.2 / RFC 6793 §3',
  },
  holdTime: {
    summary:
      'Maximum seconds allowed between successive KEEPALIVE or UPDATE messages before tearing down the session. Must be 0 (disabled) or at least 3 (commonly 90 or 180).',
    reference: 'RFC 4271 §4.2',
  },
  bgpIdentifier: {
    summary:
      '32-bit router ID formatted like an IPv4 address that uniquely identifies the BGP speaker within its Autonomous System.',
    reference: 'RFC 4271 §4.2',
  },
  optParamLength: {
    summary:
      '1-byte length of the Optional Parameters (such as Capabilities) following the fixed OPEN header. Zero when no optional parameters are sent.',
    reference: 'RFC 4271 §4.2',
  },
  withdrawnRoutesLength: {
    summary:
      '2-byte length of the Withdrawn Routes section listing IPv4 prefixes being removed from service. Zero when no routes are withdrawn.',
    reference: 'RFC 4271 §4.3',
  },
  totalPathAttrLength: {
    summary:
      '2-byte length of the Path Attributes section (such as ORIGIN, AS_PATH, and NEXT_HOP) describing announced routes.',
    reference: 'RFC 4271 §4.3',
  },
  errorCode: {
    summary:
      '1-byte category explaining why a BGP session is being closed (1-6 in RFC 4271, such as 2 = OPEN Message Error or 4 = Hold Timer Expired; 7 = Route Refresh Error).',
    reference: 'RFC 4271 §4.5 / RFC 7313 §5',
  },
  errorSubcode: {
    summary:
      '1-byte detail code refining the Error Code in a NOTIFICATION message, or 0 for an unspecific error.',
    reference: 'RFC 4271 §4.5',
  },
};

export function createDefaultBGP(): BGPLayer {
  return {
    type: 'bgp',
    bgpType: 1,
    marker: autoValue(),
    length: autoValue(),
    version: autoValue(),
    myAs: 65001,
    holdTime: 180,
    bgpIdentifier: '192.168.0.1',
    optParamLength: autoValue(),
    withdrawnRoutesLength: autoValue(),
    totalPathAttrLength: autoValue(),
    errorCode: 6,
    errorSubcode: 4,
  };
}

export function getBGPHeaderLength(bgpType: BGPMessageType): number {
  switch (bgpType) {
    case BGP_TYPE_OPEN:
      return BGP_OPEN_HEADER_LENGTH;
    case BGP_TYPE_UPDATE:
      return BGP_UPDATE_HEADER_LENGTH;
    case BGP_TYPE_NOTIFICATION:
      return BGP_NOTIFICATION_HEADER_LENGTH;
    case BGP_TYPE_KEEPALIVE:
      return BGP_KEEPALIVE_HEADER_LENGTH;
  }
}

export type BGPUnderlyingTCPContext = TCPTransportContext;

export interface EncodeBGPContext {
  readonly layerIndex: number;
  readonly upperBytesLength: number;
  /** Immediately preceding TCP layer state for RFC 4271 transport / port 179 hints */
  readonly tcp: BGPUnderlyingTCPContext;
}

export function isAllFF(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0xff) return false;
  }
  return true;
}

/**
 * Encodes a BGP-4 message header and fixed body (RFC 4271 §4.1-4.5).
 */
export function encodeBGP(layer: BGPLayer, ctx: EncodeBGPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  if (ctx.tcp.status === 'absent') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: 'No underlying TCP layer; BGP-4 runs over TCP port 179 (RFC 4271).',
    });
  } else if (
    ctx.tcp.status === 'valid' &&
    ctx.tcp.srcPort !== BGP_PORT &&
    ctx.tcp.dstPort !== BGP_PORT
  ) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: `Underlying TCP ports are ${ctx.tcp.srcPort} -> ${ctx.tcp.dstPort}; BGP-4 normally uses TCP port 179 (RFC 4271).`,
    });
  }

  // 1) Marker (16 bytes, auto = all 0xff per RFC 4271 §4.1)
  let markerBytes: Uint8Array = new Uint8Array(16).fill(0xff);
  if (layer.marker.mode === 'manual') {
    const parsedMarker = parseHexBytes(layer.marker.value);
    if (!parsedMarker.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'marker', message: parsedMarker.error });
    } else if (parsedMarker.value.length !== 16) {
      errors.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'marker',
        message: `BGP Marker must be exactly 16 bytes / 32 hex digits (got ${parsedMarker.value.length} bytes).`,
      });
    } else {
      markerBytes = parsedMarker.value;
      if (!isAllFF(markerBytes)) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'marker',
          message: 'Manual BGP Marker is not all-ones (RFC 4271 §4.1 requires 16 bytes of 0xff).',
        });
      }
    }
  }

  // 2) Length (16-bit, RFC 4271 §4.1: min 19, standard max 4096, extended RFC 8654 max 65535)
  const headerLength = getBGPHeaderLength(layer.bgpType);
  const actualLength = headerLength + ctx.upperBytesLength;
  if (actualLength > 0xffff) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'length',
      message: `BGP message length exceeds 65535 bytes (got ${actualLength} bytes).`,
    });
  } else if (actualLength > BGP_RFC4271_MAX_LENGTH && layer.length.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'length',
      message: `BGP message length (${actualLength} bytes) exceeds the RFC 4271 §4.1 limit of 4096 bytes (requires RFC 8654 Extended Messages).`,
    });
  }

  let lengthValue = actualLength;
  if (layer.length.mode === 'manual') {
    const lenErr = validateUintRange(layer.length.value, 0xffff, 'BGP Length');
    if (lenErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'length', message: lenErr });
    } else {
      lengthValue = layer.length.value;
      if (lengthValue < BGP_COMMON_HEADER_LENGTH) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `Manual BGP Length (${lengthValue}) is smaller than the 19-byte header minimum (RFC 4271 §4.1).`,
        });
      } else if (lengthValue > BGP_RFC4271_MAX_LENGTH) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `Manual BGP Length (${lengthValue}) exceeds the RFC 4271 §4.1 limit of 4096 bytes (requires RFC 8654 Extended Messages).`,
        });
      } else if (actualLength <= 0xffff && lengthValue !== actualLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `Using manual BGP Length ${lengthValue} (actual message length is ${actualLength} bytes).`,
        });
      }
    }
  }

  const resolvedAutoValues: Record<string, number> = {
    length: actualLength,
  };

  // 3) Type-specific field validation & encoding
  if (layer.bgpType === BGP_TYPE_OPEN) {
    let versionValue = BGP_VERSION_4;
    if (layer.version.mode === 'manual') {
      const verErr = validateUintRange(layer.version.value, 0xff, 'BGP Version');
      if (verErr !== null) {
        errors.push({ layerIndex: ctx.layerIndex, fieldId: 'version', message: verErr });
      } else {
        versionValue = layer.version.value;
        if (versionValue !== BGP_VERSION_4) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: 'version',
            message: `Using manual BGP Version ${versionValue} (BGP-4 is 4 per RFC 4271 §4.2).`,
          });
        }
      }
    }
    resolvedAutoValues.version = BGP_VERSION_4;

    const asErr = validateUintRange(layer.myAs, 0xffff, 'My AS');
    if (asErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'myAs', message: asErr });
    }

    const holdErr = validateUintRange(layer.holdTime, 0xffff, 'Hold Time');
    if (holdErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'holdTime', message: holdErr });
    } else if (layer.holdTime === 1 || layer.holdTime === 2) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'holdTime',
        message: `Hold Time of ${layer.holdTime}s is unacceptable per RFC 4271 §4.2 (must be 0 or at least 3 seconds).`,
      });
    }

    const bgpIdRes = parseIPv4(layer.bgpIdentifier);
    if (!bgpIdRes.ok) {
      errors.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'bgpIdentifier',
        message: bgpIdRes.error,
      });
    }

    const actualOptLen = ctx.upperBytesLength;
    let optLenValue = actualOptLen;
    if (layer.optParamLength.mode === 'auto') {
      if (actualOptLen > 0xff) {
        errors.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'optParamLength',
          message: `OPEN Optional Parameters Length exceeds 255 bytes (got ${actualOptLen} bytes, RFC 4271 §4.2).`,
        });
      }
    } else {
      const optErr = validateUintRange(layer.optParamLength.value, 0xff, 'Optional Parameters Length');
      if (optErr !== null) {
        errors.push({ layerIndex: ctx.layerIndex, fieldId: 'optParamLength', message: optErr });
      } else {
        optLenValue = layer.optParamLength.value;
        if (optLenValue !== actualOptLen) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: 'optParamLength',
            message: `Using manual Optional Parameters Length ${optLenValue} (actual payload length is ${actualOptLen} bytes).`,
          });
        }
      }
    }
    resolvedAutoValues.optParamLength = actualOptLen;

    if (errors.length > 0 || !bgpIdRes.ok) {
      return { ok: false, errors, warnings };
    }

    const buf = new Uint8Array(BGP_OPEN_HEADER_LENGTH);
    buf.set(markerBytes, 0);
    writeUint16BE(buf, 16, lengthValue);
    buf[18] = BGP_TYPE_OPEN;
    buf[19] = versionValue;
    writeUint16BE(buf, 20, layer.myAs);
    writeUint16BE(buf, 22, layer.holdTime);
    buf.set(bgpIdRes.value, 24);
    buf[28] = optLenValue;

    return {
      ok: true,
      bytes: buf,
      spans: BGP_OPEN_FIELD_SPANS,
      warnings,
      resolvedAutoValues,
    };
  }

  if (layer.bgpType === BGP_TYPE_UPDATE) {
    let withdrawnLen = 0;
    if (layer.withdrawnRoutesLength.mode === 'manual') {
      const wErr = validateUintRange(
        layer.withdrawnRoutesLength.value,
        0xffff,
        'Withdrawn Routes Length',
      );
      if (wErr !== null) {
        errors.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'withdrawnRoutesLength',
          message: wErr,
        });
      } else {
        withdrawnLen = layer.withdrawnRoutesLength.value;
        if (withdrawnLen > 0) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: 'withdrawnRoutesLength',
            message:
              'In RFC 4271 §4.3, non-zero Withdrawn Routes sit between Withdrawn Routes Length and Total Path Attribute Length; this fixed 23-byte header places both length fields before Payload (wire-accurate when Withdrawn Routes Length = 0).',
          });
        }
      }
    }
    resolvedAutoValues.withdrawnRoutesLength = 0;

    let attrLen = 0;
    if (layer.totalPathAttrLength.mode === 'manual') {
      const aErr = validateUintRange(
        layer.totalPathAttrLength.value,
        0xffff,
        'Total Path Attribute Length',
      );
      if (aErr !== null) {
        errors.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'totalPathAttrLength',
          message: aErr,
        });
      } else {
        attrLen = layer.totalPathAttrLength.value;
      }
    }
    resolvedAutoValues.totalPathAttrLength = 0;

    if (errors.length === 0 && withdrawnLen + attrLen > ctx.upperBytesLength) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        message: `Withdrawn Routes Length (${withdrawnLen}) + Total Path Attribute Length (${attrLen}) exceeds available payload (${ctx.upperBytesLength} bytes, RFC 4271 §4.3).`,
      });
    }

    if (errors.length > 0) {
      return { ok: false, errors, warnings };
    }

    const buf = new Uint8Array(BGP_UPDATE_HEADER_LENGTH);
    buf.set(markerBytes, 0);
    writeUint16BE(buf, 16, lengthValue);
    buf[18] = BGP_TYPE_UPDATE;
    writeUint16BE(buf, 19, withdrawnLen);
    writeUint16BE(buf, 21, attrLen);

    return {
      ok: true,
      bytes: buf,
      spans: BGP_UPDATE_FIELD_SPANS,
      warnings,
      resolvedAutoValues,
    };
  }

  if (layer.bgpType === BGP_TYPE_NOTIFICATION) {
    const codeErr = validateUintRange(layer.errorCode, 0xff, 'Error Code');
    if (codeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'errorCode', message: codeErr });
    }
    const subErr = validateUintRange(layer.errorSubcode, 0xff, 'Error Subcode');
    if (subErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'errorSubcode', message: subErr });
    }

    if (errors.length > 0) {
      return { ok: false, errors, warnings };
    }

    const buf = new Uint8Array(BGP_NOTIFICATION_HEADER_LENGTH);
    buf.set(markerBytes, 0);
    writeUint16BE(buf, 16, lengthValue);
    buf[18] = BGP_TYPE_NOTIFICATION;
    buf[19] = layer.errorCode;
    buf[20] = layer.errorSubcode;

    return {
      ok: true,
      bytes: buf,
      spans: BGP_NOTIFICATION_FIELD_SPANS,
      warnings,
      resolvedAutoValues,
    };
  }

  // Type 4: KEEPALIVE (RFC 4271 §4.4)
  if (ctx.upperBytesLength > 0) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: `KEEPALIVE messages must have Length=19 and no payload (got ${ctx.upperBytesLength} payload bytes, RFC 4271 §4.4).`,
    });
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const buf = new Uint8Array(BGP_KEEPALIVE_HEADER_LENGTH);
  buf.set(markerBytes, 0);
  writeUint16BE(buf, 16, lengthValue);
  buf[18] = BGP_TYPE_KEEPALIVE;

  return {
    ok: true,
    bytes: buf,
    spans: BGP_KEEPALIVE_FIELD_SPANS,
    warnings,
    resolvedAutoValues,
  };
}

function isBGPMessageType(value: number): value is BGPMessageType {
  return (
    value === BGP_TYPE_OPEN ||
    value === BGP_TYPE_UPDATE ||
    value === BGP_TYPE_NOTIFICATION ||
    value === BGP_TYPE_KEEPALIVE
  );
}

function validateBGPPermalink(raw: Record<string, unknown>, ctx: string): Result<BGPLayer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'bgpType',
      'marker',
      'length',
      'version',
      'myAs',
      'holdTime',
      'bgpIdentifier',
      'optParamLength',
      'withdrawnRoutesLength',
      'totalPathAttrLength',
      'errorCode',
      'errorSubcode',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const bgpTypeRaw = obj.bgpType;
  if (bgpTypeRaw !== 1 && bgpTypeRaw !== 2 && bgpTypeRaw !== 3 && bgpTypeRaw !== 4) {
    return err(`${ctx}.bgpType must be 1, 2, 3, or 4.`);
  }
  const bgpType: BGPMessageType = bgpTypeRaw;
  const marker = validateAutoOrManualString(obj.marker, `${ctx}.marker`);
  if (!marker.ok) return marker;
  const length = validateAutoOrManualNumber(obj.length, `${ctx}.length`);
  if (!length.ok) return length;
  const version = validateAutoOrManualNumber(obj.version, `${ctx}.version`);
  if (!version.ok) return version;
  const myAs = expectNumber(obj, 'myAs', ctx);
  if (!myAs.ok) return myAs;
  const holdTime = expectNumber(obj, 'holdTime', ctx);
  if (!holdTime.ok) return holdTime;
  const bgpIdentifier = expectString(obj, 'bgpIdentifier', ctx);
  if (!bgpIdentifier.ok) return bgpIdentifier;
  const optParamLength = validateAutoOrManualNumber(obj.optParamLength, `${ctx}.optParamLength`);
  if (!optParamLength.ok) return optParamLength;
  const withdrawnRoutesLength = validateAutoOrManualNumber(
    obj.withdrawnRoutesLength,
    `${ctx}.withdrawnRoutesLength`,
  );
  if (!withdrawnRoutesLength.ok) return withdrawnRoutesLength;
  const totalPathAttrLength = validateAutoOrManualNumber(
    obj.totalPathAttrLength,
    `${ctx}.totalPathAttrLength`,
  );
  if (!totalPathAttrLength.ok) return totalPathAttrLength;
  const errorCode = expectNumber(obj, 'errorCode', ctx);
  if (!errorCode.ok) return errorCode;
  const errorSubcode = expectNumber(obj, 'errorSubcode', ctx);
  if (!errorSubcode.ok) return errorSubcode;
  return ok({
    type: 'bgp',
    bgpType,
    marker: marker.value,
    length: length.value,
    version: version.value,
    myAs: myAs.value,
    holdTime: holdTime.value,
    bgpIdentifier: bgpIdentifier.value,
    optParamLength: optParamLength.value,
    withdrawnRoutesLength: withdrawnRoutesLength.value,
    totalPathAttrLength: totalPathAttrLength.value,
    errorCode: errorCode.value,
    errorSubcode: errorSubcode.value,
  });
}

export const bgpDefinition: LayerDefinition<BGPLayer, 'bgp'> = {
  type: 'bgp',
  minHeaderLength: BGP_COMMON_HEADER_LENGTH,
  createDefault: createDefaultBGP,
  headerLength: (layer) => getBGPHeaderLength(layer.bgpType),
  encode: (layer, ctx) =>
    encodeBGP(layer, {
      layerIndex: ctx.layerIndex,
      upperBytesLength: ctx.upperBytesLength,
      tcp: ctx.tcp,
    }),
  decode(bytes, offset, ctx) {
    const tcpPayload = bytes.subarray(offset);
    if (tcpPayload.length === 0) {
      return null;
    }

    if (ctx.tcpDataOffsetAuto === false) {
      if (
        ctx.tcpDataOffsetValue !== undefined &&
        ctx.tcpDataOffsetValue < MIN_VALID_TCP_DATA_OFFSET
      ) {
        ctx.notes.push(
          `TCP segment on port ${BGP_PORT} has invalid Data Offset (${ctx.tcpDataOffsetValue}); BGP-4 decoding skipped.`,
        );
      }
      return null;
    }

    // RFC 4271 §4.1: BGP messages begin with a 16-octet all-ones Marker (0xff * 16).
    if (tcpPayload.length < 16 || !isAllFF(tcpPayload.subarray(0, 16))) {
      return null;
    }

    if (tcpPayload.length < BGP_COMMON_HEADER_LENGTH) {
      ctx.notes.push(
        `BGP-4 message on TCP port ${BGP_PORT} is truncated (${tcpPayload.length} bytes, need at least ${BGP_COMMON_HEADER_LENGTH}); remaining bytes kept as Payload.`,
      );
      return null;
    }

    const bgpLength = readUint16BE(tcpPayload, 16);
    const rawType = tcpPayload[18];

    if (!isBGPMessageType(rawType)) {
      ctx.notes.push(
        `BGP message Type ${rawType} is not decoded into a layer (supported: 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE); remaining bytes kept as Payload.`,
      );
      return null;
    }

    const headerLen = getBGPHeaderLength(rawType);
    if (tcpPayload.length < headerLen) {
      ctx.notes.push(
        `BGP-4 ${BGP_TYPE_NAMES[rawType]} message on TCP port ${BGP_PORT} is truncated (${tcpPayload.length} bytes, need at least ${headerLen}); remaining bytes kept as Payload.`,
      );
      return null;
    }

    if (bgpLength < headerLen) {
      ctx.notes.push(
        `BGP Length (${bgpLength}) is smaller than the ${headerLen}-byte ${BGP_TYPE_NAMES[rawType]} header; kept as manual Length.`,
      );
    } else if (bgpLength < tcpPayload.length) {
      ctx.notes.push(
        `BGP Length (${bgpLength}) is smaller than TCP payload (${tcpPayload.length} bytes); additional bytes (e.g., pipelined BGP messages) are preserved in Payload.`,
      );
    } else if (bgpLength > tcpPayload.length) {
      ctx.notes.push(
        `BGP Length (${bgpLength}) exceeds available TCP payload (${tcpPayload.length} bytes); kept as manual Length.`,
      );
    }

    const baseLayer: BGPLayer = {
      type: 'bgp',
      bgpType: rawType,
      marker: autoValue<string>(),
      length: bgpLength === tcpPayload.length ? autoValue() : manualValue(bgpLength),
      version: autoValue(),
      myAs: 65001,
      holdTime: 180,
      bgpIdentifier: '192.0.2.1',
      optParamLength: autoValue(),
      withdrawnRoutesLength: autoValue(),
      totalPathAttrLength: autoValue(),
      errorCode: 6,
      errorSubcode: 0,
    };

    if (rawType === BGP_TYPE_OPEN) {
      const versionByte = tcpPayload[19];
      const myAs = readUint16BE(tcpPayload, 20);
      const holdTime = readUint16BE(tcpPayload, 22);
      const bgpIdentifier = formatIPv4(tcpPayload.subarray(24, 28));
      const optParamLen = tcpPayload[28];
      const remainingPayload = tcpPayload.slice(headerLen);

      return {
        layers: [
          {
            ...baseLayer,
            version: versionByte === BGP_VERSION_4 ? autoValue() : manualValue(versionByte),
            myAs,
            holdTime,
            bgpIdentifier,
            optParamLength:
              optParamLen === remainingPayload.length ? autoValue() : manualValue(optParamLen),
          },
        ],
        payload: remainingPayload,
      };
    }

    if (rawType === BGP_TYPE_UPDATE) {
      const withdrawnLen = readUint16BE(tcpPayload, 19);
      const attrLen = readUint16BE(tcpPayload, 21);
      const remainingPayload = tcpPayload.slice(headerLen);

      if (withdrawnLen > 0) {
        ctx.notes.push(
          `BGP UPDATE has non-zero Withdrawn Routes Length (${withdrawnLen}); RFC 4271 §4.3 places Withdrawn Routes before Total Path Attribute Length, so bytes 21..22 were preserved in Total Path Attribute Length for lossless round-trip.`,
        );
      }

      return {
        layers: [
          {
            ...baseLayer,
            withdrawnRoutesLength: withdrawnLen === 0 ? autoValue() : manualValue(withdrawnLen),
            totalPathAttrLength: attrLen === 0 ? autoValue() : manualValue(attrLen),
          },
        ],
        payload: remainingPayload,
      };
    }

    if (rawType === BGP_TYPE_NOTIFICATION) {
      const errorCode = tcpPayload[19];
      const errorSubcode = tcpPayload[20];
      return {
        layers: [
          {
            ...baseLayer,
            errorCode,
            errorSubcode,
          },
        ],
        payload: tcpPayload.slice(headerLen),
      };
    }

    // Type 4: KEEPALIVE
    return {
      layers: [baseLayer],
      payload: tcpPayload.slice(headerLen),
    };
  },
  validatePermalink: validateBGPPermalink,
  fieldDocs: BGP_FIELD_DOCS,
  protocols: {
    tcpPort: BGP_PORT,
  },
};
