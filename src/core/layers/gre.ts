import { concatBytes, writeUint16BE, writeUint32BE } from '../bytes';
import { internetChecksum } from '../checksum';
import {
  ETHERTYPE_ARP,
  ETHERTYPE_IPV4,
  ETHERTYPE_IPV6,
  ETHERTYPE_VLAN,
} from './ethernet';
import type {
  GRELayer,
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** Minimum GRE header length (flags/version + protocol type, 4 bytes, RFC 2784 §2) */
export const GRE_BASE_HEADER_LENGTH = 4;
/** Maximum 3-bit GRE version field value */
export const GRE_MAX_VERSION = 7;
/** Transparent Ethernet Bridging (GRETAP) EtherType (RFC 1701 / IANA IEEE 802 Numbers) */
export const GRE_PROTOCOL_TEB = 0x6558;

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
export function greProtocolTypeForUpperLayer(upperLayerType: LayerType | null): number | null {
  switch (upperLayerType) {
    case 'ipv4':
      return ETHERTYPE_IPV4;
    case 'ipv6':
      return ETHERTYPE_IPV6;
    case 'arp':
      return ETHERTYPE_ARP;
    case 'ethernet':
      return GRE_PROTOCOL_TEB;
    case 'vlan':
      return ETHERTYPE_VLAN;
    default:
      return null;
  }
}

function upperLayerNameForGRE(upperLayerType: LayerType | null): string {
  switch (upperLayerType) {
    case 'ipv6':
      return 'IPv6';
    case 'arp':
      return 'ARP';
    case 'ethernet':
      return 'Ethernet II (Transparent Ethernet Bridging)';
    case 'vlan':
      return '802.1Q VLAN';
    default:
      return 'IPv4';
  }
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
  readonly upperLayerType: LayerType | null;
  readonly upperBytes: Uint8Array;
}

/**
 * Encodes a Generic Routing Encapsulation (GRE) header (4-16 bytes, RFC 2784 / RFC 2890).
 */
export function encodeGRE(layer: GRELayer, ctx: EncodeGREContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

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

  const inferredProtocolType = greProtocolTypeForUpperLayer(ctx.upperLayerType);
  const autoProtocolType = inferredProtocolType ?? ETHERTYPE_IPV4;
  let protocolTypeValue = autoProtocolType;

  if (layer.protocolType.mode === 'manual') {
    const ptErr = validateUintRange(layer.protocolType.value, 0xffff, 'Protocol Type');
    if (ptErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocolType', message: ptErr });
    } else {
      protocolTypeValue = layer.protocolType.value;
      if (inferredProtocolType !== null && protocolTypeValue !== inferredProtocolType) {
        const expectedHex = `0x${inferredProtocolType.toString(16).padStart(4, '0')}`;
        const upperName = upperLayerNameForGRE(ctx.upperLayerType);
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'protocolType',
          message: `Using manual Protocol Type 0x${protocolTypeValue.toString(16).padStart(4, '0')} (standard ${upperName} value is ${expectedHex}).`,
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
