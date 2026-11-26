import {
  concatBytes,
  readUint16BE,
  readUint32BE,
  writeUint16BE,
  writeUint32BE,
} from '../../bytes';
import { internetChecksum } from '../../checksum';
import { ok, type Result } from '../../result';
import {
  MAX_IP_LAYERS,
  type FieldDoc,
  type LayerDefinition,
  type ProtocolTables,
} from '../definition';
import {
  expectBoolean,
  expectNumber,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import { getDefaultProtocolTables } from '../registry';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type GRELayer,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

/** Minimum GRE header length (flags/version + protocol type, 4 bytes, RFC 2784 §2) */
export const GRE_BASE_HEADER_LENGTH = 4;
/** Maximum 3-bit GRE version field value */
export const GRE_MAX_VERSION = 7;
/** IANA IP Protocol / IPv6 Next Header number for GRE (RFC 2784) */
export const IP_PROTOCOL_GRE = 47;
export { GRE_PROTOCOL_TEB } from '../ethernet';

export const GRE_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  checksumPresent: {
    summary:
      '1-bit Checksum Present flag (C, bit 0). When set to 1, appends the 16-bit Checksum and 16-bit Reserved1 fields (+4 bytes) immediately after Protocol Type.',
    reference: 'RFC 2784 §2.2',
  },
  keyPresent: {
    summary:
      '1-bit Key Present flag (K, bit 2). When set to 1, appends a 32-bit Key field (+4 bytes) to identify an individual traffic flow or tunnel instance.',
    reference: 'RFC 2890 §2.1',
  },
  sequencePresent: {
    summary:
      '1-bit Sequence Number Present flag (S, bit 3). When set to 1, appends a 32-bit Sequence Number field (+4 bytes) for packet ordering detection.',
    reference: 'RFC 2890 §2.2',
  },
  reserved0: {
    summary:
      'Reserved header bits (bit 1 and bits 4-12, 10 bits total) that must be transmitted as 0 in standard GRE.',
    reference: 'RFC 2784 §2.3 / RFC 2890 §2',
  },
  version: {
    summary:
      '3-bit GRE Version Number (bits 13-15). Must be 0 for standard RFC 2784 GRE (Version 1 is PPTP enhanced GRE).',
    reference: 'RFC 2784 §2.3.1',
  },
  protocolType: {
    summary:
      '16-bit EtherType declaring the encapsulated payload protocol: 0x0800 (IPv4), 0x86dd (IPv6), 0x6558 (Transparent Ethernet Bridging / GRETAP), 0x0806 (ARP), or 0x8100 (802.1Q VLAN).',
    reference: 'RFC 2784 §2.4',
  },
  checksum: {
    summary:
      "Optional 16-bit RFC 1071 one's-complement checksum (present when C=1) computed over the entire GRE header (with Checksum=0) and encapsulated payload packet.",
    reference: 'RFC 2784 §2.5',
  },
  reserved1: {
    summary:
      'Optional 16-bit Reserved1 field (present when C=1) that follows Checksum and must be set to 0.',
    reference: 'RFC 2784 §2.6',
  },
  key: {
    summary:
      'Optional 32-bit tunnel key (present when K=1) assigned by the encapsulator to multiplex or authenticate individual flows within a GRE tunnel.',
    reference: 'RFC 2890 §2.1',
  },
  sequenceNumber: {
    summary:
      'Optional 32-bit unsigned sequence counter (present when S=1) incremented for each GRE packet to detect reordering or loss.',
    reference: 'RFC 2890 §2.2',
  },
};

/** Creates a default GRE header (4-byte base header, Version 0, auto Protocol Type, RFC 2784). */
export function createDefaultGRE(): GRELayer {
  return {
    type: 'gre',
    checksumPresent: false,
    keyPresent: false,
    sequencePresent: false,
    version: autoValue(),
    protocolType: autoValue(),
    checksum: autoValue(),
    key: 0,
    sequenceNumber: 0,
  };
}

/**
 * Computes the GRE header length in bytes (4, 8, 12, or 16) from the optional C / K / S flags.
 * - Base header: 4 bytes (RFC 2784 §2)
 * - C=1: +4 bytes (Checksum 16b + Reserved1 16b, RFC 2784 §2.5 / §2.6)
 * - K=1: +4 bytes (Key 32b, RFC 2890 §2.1)
 * - S=1: +4 bytes (Sequence Number 32b, RFC 2890 §2.2)
 */
export function getGREHeaderLength(
  layer: Pick<GRELayer, 'checksumPresent' | 'keyPresent' | 'sequencePresent'>,
): number {
  return (
    GRE_BASE_HEADER_LENGTH +
    (layer.checksumPresent ? 4 : 0) +
    (layer.keyPresent ? 4 : 0) +
    (layer.sequencePresent ? 4 : 0)
  );
}

/**
 * Returns the standard GRE Protocol Type (EtherType) for the immediately following upper layer.
 */
export function greProtocolTypeForUpperLayer(
  upperLayerType: string | null,
  tables: ProtocolTables = getDefaultProtocolTables(),
): number | null {
  return tables.resolveGreProtocolType(upperLayerType)?.value ?? null;
}

/**
 * Builds contiguous bit spans for the GRE header across all 8 combinations of C / K / S.
 * Base 32 bits (RFC 2784 §2 / RFC 2890 §2):
 *   C (1b) | Reserved0 bit 1 (1b) | K (1b) | S (1b) | Reserved0 (9b) | Ver (3b) | Protocol Type (16b)
 */
export function buildGREFieldSpans(
  layer: Pick<GRELayer, 'checksumPresent' | 'keyPresent' | 'sequencePresent'>,
): RelativeFieldSpan[] {
  const spans: RelativeFieldSpan[] = [
    { fieldId: 'checksumPresent', label: 'C', bitOffset: 0, bitLength: 1 },
    { fieldId: 'reserved0', label: '0', bitOffset: 1, bitLength: 1 },
    { fieldId: 'keyPresent', label: 'K', bitOffset: 2, bitLength: 1 },
    { fieldId: 'sequencePresent', label: 'S', bitOffset: 3, bitLength: 1 },
    { fieldId: 'reserved0', label: 'Reserved0', bitOffset: 4, bitLength: 9 },
    { fieldId: 'version', label: 'Ver', bitOffset: 13, bitLength: 3 },
    { fieldId: 'protocolType', label: 'Protocol Type', bitOffset: 16, bitLength: 16 },
  ];

  let bitCursor = 32;
  if (layer.checksumPresent) {
    spans.push(
      { fieldId: 'checksum', label: 'Checksum', bitOffset: bitCursor, bitLength: 16 },
      { fieldId: 'reserved1', label: 'Reserved1', bitOffset: bitCursor + 16, bitLength: 16 },
    );
    bitCursor += 32;
  }
  if (layer.keyPresent) {
    spans.push({ fieldId: 'key', label: 'Key', bitOffset: bitCursor, bitLength: 32 });
    bitCursor += 32;
  }
  if (layer.sequencePresent) {
    spans.push({
      fieldId: 'sequenceNumber',
      label: 'Sequence Number',
      bitOffset: bitCursor,
      bitLength: 32,
    });
  }

  return spans;
}

export interface EncodeGREContext {
  readonly layerIndex: number;
  readonly upperLayerType: string | null;
  readonly upperBytes: Uint8Array;
  readonly tables?: ProtocolTables;
}

/**
 * Encodes a Generic Routing Encapsulation (GRE) header (4-16 bytes, RFC 2784 / RFC 2890).
 */
export function encodeGRE(layer: GRELayer, ctx: EncodeGREContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];
  const tables = ctx.tables ?? getDefaultProtocolTables();

  const autoVersion = 0;
  let versionValue = autoVersion;
  if (layer.version.mode === 'manual') {
    const verErr = validateUintRange(layer.version.value, GRE_MAX_VERSION, 'GRE Version');
    if (verErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'version', message: verErr });
    } else {
      versionValue = layer.version.value;
      if (versionValue !== 0) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'version',
          message: `GRE Version is ${versionValue}; RFC 2784 §2.3.1 requires Version = 0 for standard GRE.`,
        });
      }
    }
  }

  const resolved = tables.resolveGreProtocolType(ctx.upperLayerType);
  const inferredProtocolType = resolved?.value ?? null;
  const autoProtocolType = inferredProtocolType ?? tables.defaultEtherType;
  let protocolTypeValue = autoProtocolType;

  if (layer.protocolType.mode === 'manual') {
    const ptErr = validateUintRange(layer.protocolType.value, 0xffff, 'Protocol Type');
    if (ptErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocolType', message: ptErr });
    } else {
      protocolTypeValue = layer.protocolType.value;
      if (resolved !== null && protocolTypeValue !== resolved.value) {
        const expectedHex = `0x${resolved.value.toString(16).padStart(4, '0')}`;
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'protocolType',
          message: `Using manual Protocol Type 0x${protocolTypeValue.toString(16).padStart(4, '0')} (standard ${resolved.label} value is ${expectedHex}).`,
        });
      }
    }
  } else if (inferredProtocolType === null) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'protocolType',
      message:
        'Upper layer is not IPv4, IPv6, Ethernet II, ARP, or VLAN; defaulting Protocol Type to 0x0800.',
    });
  }

  if (layer.checksumPresent && layer.checksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.checksum.value, 0xffff, 'GRE Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumErr });
    }
  }

  if (layer.keyPresent) {
    const keyErr = validateUintRange(layer.key, 0xffffffff, 'GRE Key');
    if (keyErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'key', message: keyErr });
    }
  }

  if (layer.sequencePresent) {
    const seqErr = validateUintRange(layer.sequenceNumber, 0xffffffff, 'Sequence Number');
    if (seqErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'sequenceNumber', message: seqErr });
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const headerLength = getGREHeaderLength(layer);
  const header = new Uint8Array(headerLength);

  const flagsAndVersion =
    (layer.checksumPresent ? 0x8000 : 0) |
    (layer.keyPresent ? 0x2000 : 0) |
    (layer.sequencePresent ? 0x1000 : 0) |
    (versionValue & 0x7);

  writeUint16BE(header, 0, flagsAndVersion);
  writeUint16BE(header, 2, protocolTypeValue);

  let offset = GRE_BASE_HEADER_LENGTH;
  let checksumOffset = -1;
  if (layer.checksumPresent) {
    checksumOffset = offset;
    // Checksum (16b) and Reserved1 (16b) start at 0 for RFC 2784 §2.5 checksum computation
    offset += 4;
  }
  if (layer.keyPresent) {
    writeUint32BE(header, offset, layer.key);
    offset += 4;
  }
  if (layer.sequencePresent) {
    writeUint32BE(header, offset, layer.sequenceNumber);
  }

  const resolvedAutoValues: Record<string, number> = {
    version: autoVersion,
    protocolType: autoProtocolType,
  };

  if (layer.checksumPresent && checksumOffset >= 0) {
    const autoChecksum = internetChecksum(concatBytes(header, ctx.upperBytes));
    const checksumValue =
      layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
    writeUint16BE(header, checksumOffset, checksumValue);
    resolvedAutoValues.checksum = autoChecksum;

    if (layer.checksum.mode === 'manual' && checksumValue !== autoChecksum) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'checksum',
        message: `Using manual GRE Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed RFC 2784 §2.5 value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
      });
    }
  }

  return {
    ok: true,
    bytes: header,
    spans: buildGREFieldSpans(layer),
    warnings,
    resolvedAutoValues,
  };
}

function validateGREPermalink(raw: Record<string, unknown>, ctx: string): Result<GRELayer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'checksumPresent',
      'keyPresent',
      'sequencePresent',
      'version',
      'protocolType',
      'checksum',
      'key',
      'sequenceNumber',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const checksumPresent = expectBoolean(obj, 'checksumPresent', ctx);
  if (!checksumPresent.ok) return checksumPresent;
  const keyPresent = expectBoolean(obj, 'keyPresent', ctx);
  if (!keyPresent.ok) return keyPresent;
  const sequencePresent = expectBoolean(obj, 'sequencePresent', ctx);
  if (!sequencePresent.ok) return sequencePresent;
  const version = validateAutoOrManualNumber(obj.version, `${ctx}.version`);
  if (!version.ok) return version;
  const protocolType = validateAutoOrManualNumber(obj.protocolType, `${ctx}.protocolType`);
  if (!protocolType.ok) return protocolType;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const key = expectNumber(obj, 'key', ctx);
  if (!key.ok) return key;
  const sequenceNumber = expectNumber(obj, 'sequenceNumber', ctx);
  if (!sequenceNumber.ok) return sequenceNumber;

  return ok({
    type: 'gre',
    checksumPresent: checksumPresent.value,
    keyPresent: keyPresent.value,
    sequencePresent: sequencePresent.value,
    version: version.value,
    protocolType: protocolType.value,
    checksum: checksum.value,
    key: key.value,
    sequenceNumber: sequenceNumber.value,
  });
}

export const greDefinition: LayerDefinition<GRELayer, 'gre'> = {
  type: 'gre',
  minHeaderLength: GRE_BASE_HEADER_LENGTH,
  createDefault: createDefaultGRE,
  headerLength: (layer) => getGREHeaderLength(layer),
  encode: (layer, ctx) =>
    encodeGRE(layer, {
      layerIndex: ctx.layerIndex,
      upperLayerType: ctx.upperLayerType,
      upperBytes: ctx.upperBytes,
      tables: ctx.tables,
    }),
  decode(bytes, offset, ctx) {
    const remaining = bytes.length - offset;
    const flagsAndVersion = readUint16BE(bytes, offset);
    const protocolType = readUint16BE(bytes, offset + 2);

    const checksumPresent = (flagsAndVersion & 0x8000) !== 0;
    const reservedBit1 = (flagsAndVersion & 0x4000) !== 0;
    const keyPresent = (flagsAndVersion & 0x2000) !== 0;
    const sequencePresent = (flagsAndVersion & 0x1000) !== 0;
    const reserved0 = (flagsAndVersion >>> 3) & 0x1ff;
    const version = flagsAndVersion & 0x7;

    if (version !== 0) {
      ctx.notes.push(
        `GRE header has Version=${version} (only Version=0 per RFC 2784 §2.3.1 is supported; e.g., Version=1 is PPTP enhanced GRE); remaining bytes kept as Payload.`,
      );
      return null;
    }

    if (reservedBit1 || reserved0 !== 0) {
      ctx.notes.push(
        `GRE header has non-zero Reserved0 bits (flags word 0x${flagsAndVersion.toString(16).padStart(4, '0')}); remaining bytes kept as Payload to preserve exact bytes.`,
      );
      return null;
    }

    const headerLength = getGREHeaderLength({
      checksumPresent,
      keyPresent,
      sequencePresent,
    });

    if (remaining < headerLength) {
      ctx.notes.push(
        `GRE header is truncated (${remaining} bytes available, ${headerLength} bytes required for C=${checksumPresent ? 1 : 0}/K=${keyPresent ? 1 : 0}/S=${sequencePresent ? 1 : 0}); remaining bytes kept as Payload.`,
      );
      return null;
    }

    let cursor = offset + GRE_BASE_HEADER_LENGTH;
    let checksumField = 0;
    let checksumOffsetInHeader = -1;
    if (checksumPresent) {
      checksumOffsetInHeader = cursor - offset;
      checksumField = readUint16BE(bytes, cursor);
      const reserved1 = readUint16BE(bytes, cursor + 2);
      if (reserved1 !== 0) {
        ctx.notes.push(
          `GRE header has non-zero Reserved1 field (0x${reserved1.toString(16).padStart(4, '0')}); remaining bytes kept as Payload to preserve exact bytes.`,
        );
        return null;
      }
      cursor += 4;
    }

    let key = 0;
    if (keyPresent) {
      key = readUint32BE(bytes, cursor);
      cursor += 4;
    }

    let sequenceNumber = 0;
    if (sequencePresent) {
      sequenceNumber = readUint32BE(bytes, cursor);
      cursor += 4;
    }

    let checksumAutoOrManual = autoValue<number>();
    if (checksumPresent) {
      const greCopy = new Uint8Array(bytes.subarray(offset));
      greCopy[checksumOffsetInHeader] = 0;
      greCopy[checksumOffsetInHeader + 1] = 0;
      const computedChecksum = internetChecksum(greCopy);
      checksumAutoOrManual =
        checksumField === computedChecksum ? autoValue() : manualValue(checksumField);
    }

    const innerOffset = offset + headerLength;
    let innerLayers: readonly { readonly type: string }[] = [];
    let innerPayload: Uint8Array;

    if (ctx.tunnelDepth + 1 >= MAX_IP_LAYERS) {
      ctx.notes.push(
        `GRE tunnel depth limit (${MAX_IP_LAYERS}) exceeded; remaining bytes kept as Payload.`,
      );
      innerPayload = bytes.slice(innerOffset);
    } else {
      const inner = ctx.decodeByGreProtocol(
        bytes,
        innerOffset,
        protocolType,
        ctx.tunnelDepth + 1,
      );
      innerLayers = inner.layers;
      innerPayload = inner.payload;
    }

    const expectedProto = ctx.tables.resolveGreProtocolType(innerLayers[0]?.type ?? null);
    const greLayer: GRELayer = {
      type: 'gre',
      checksumPresent,
      keyPresent,
      sequencePresent,
      version: autoValue(),
      protocolType:
        expectedProto !== null && protocolType === expectedProto.value
          ? autoValue()
          : manualValue(protocolType),
      checksum: checksumPresent ? checksumAutoOrManual : autoValue(),
      key,
      sequenceNumber,
    };

    return {
      layers: [greLayer, ...innerLayers],
      payload: innerPayload,
    };
  },
  validatePermalink: validateGREPermalink,
  fieldDocs: GRE_FIELD_DOCS,
  protocols: {
    ipProtocol: IP_PROTOCOL_GRE,
  },
};
