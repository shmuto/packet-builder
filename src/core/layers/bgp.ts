import { parseHexBytes, parseIPv4, writeUint16BE } from '../bytes';
import type {
  BGPLayer,
  BGPMessageType,
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

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

export interface EncodeBGPContext {
  readonly layerIndex: number;
  readonly upperBytesLength: number;
  /** Underlying TCP ports if stacked over TCP (for port 179 convention hint) */
  readonly tcpPorts: { readonly srcPort: number; readonly dstPort: number } | null;
}

function isAllFF(bytes: Uint8Array): boolean {
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

  if (
    ctx.tcpPorts !== null &&
    ctx.tcpPorts.srcPort !== BGP_PORT &&
    ctx.tcpPorts.dstPort !== BGP_PORT
  ) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      message: `Underlying TCP ports are ${ctx.tcpPorts.srcPort} -> ${ctx.tcpPorts.dstPort}; BGP-4 normally uses TCP port 179 (RFC 4271).`,
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
          message: `Manual BGP Length (${lengthValue}) exceeds the RFC 4271 §4.1 limit of 4096 bytes.`,
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
