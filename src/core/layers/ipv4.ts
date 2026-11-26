import { parseIPv4, writeUint16BE } from '../bytes';
import { internetChecksum } from '../checksum';
import type {
  IPv4Layer,
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** Fixed 20-byte IPv4 base header length (RFC 791 §3.1) */
export const IPV4_HEADER_LENGTH = 20;
export const IPV4_VERSION = 4;
export const IPV4_DEFAULT_IHL = 5;
export const IPV4_MAX_IHL = 15;

export const IP_PROTOCOL_IPIP = 4;
export const IP_PROTOCOL_TCP = 6;
export const IP_PROTOCOL_IPV6 = 41;

export const IPV4_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'version', label: 'Version (4)', bitOffset: 0, bitLength: 4 },
  { fieldId: 'ihl', label: 'IHL', bitOffset: 4, bitLength: 4 },
  { fieldId: 'tos', label: 'TOS (DSCP/ECN)', bitOffset: 8, bitLength: 8 },
  { fieldId: 'totalLength', label: 'Total Length', bitOffset: 16, bitLength: 16 },
  { fieldId: 'identification', label: 'Identification', bitOffset: 32, bitLength: 16 },
  { fieldId: 'flags', label: 'Flags', bitOffset: 48, bitLength: 3 },
  { fieldId: 'fragmentOffset', label: 'Fragment Offset', bitOffset: 51, bitLength: 13 },
  { fieldId: 'ttl', label: 'TTL', bitOffset: 64, bitLength: 8 },
  { fieldId: 'protocol', label: 'Protocol', bitOffset: 72, bitLength: 8 },
  { fieldId: 'headerChecksum', label: 'Header Checksum', bitOffset: 80, bitLength: 16 },
  { fieldId: 'srcIp', label: 'Source IPv4', bitOffset: 96, bitLength: 32 },
  { fieldId: 'dstIp', label: 'Destination IPv4', bitOffset: 128, bitLength: 32 },
];

export interface EncodeIPv4Context {
  readonly layerIndex: number;
  readonly upperLayerType: LayerType | null;
  readonly upperBytesLength: number;
}

function protocolForUpperLayer(upperLayerType: LayerType | null): number | null {
  switch (upperLayerType) {
    case 'tcp':
      return IP_PROTOCOL_TCP;
    case 'ipv4':
      return IP_PROTOCOL_IPIP;
    case 'ipv6':
      return IP_PROTOCOL_IPV6;
    default:
      return null;
  }
}

/**
 * Encodes a 20-byte IPv4 header (RFC 791 §3.1) with automatic IHL, Total Length,
 * Protocol, and RFC 1071 Header Checksum calculation.
 */
export function encodeIPv4(layer: IPv4Layer, ctx: EncodeIPv4Context): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const tosErr = validateUintRange(layer.tos, 0xff, 'TOS');
  if (tosErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'tos', message: tosErr });
  }

  const idErr = validateUintRange(layer.identification, 0xffff, 'Identification');
  if (idErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'identification', message: idErr });
  }

  const fragErr = validateUintRange(layer.fragmentOffset, 0x1fff, 'Fragment Offset');
  if (fragErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'fragmentOffset', message: fragErr });
  }

  const ttlErr = validateUintRange(layer.ttl, 0xff, 'TTL');
  if (ttlErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'ttl', message: ttlErr });
  }

  if (layer.flags.reserved) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'flags',
      message: 'IPv4 Reserved flag bit is set (RFC 791 requires 0).',
    });
  }

  const srcIpResult = parseIPv4(layer.srcIp);
  if (!srcIpResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcIp', message: srcIpResult.error });
  }

  const dstIpResult = parseIPv4(layer.dstIp);
  if (!dstIpResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstIp', message: dstIpResult.error });
  }

  let ihlValue = IPV4_DEFAULT_IHL;
  if (layer.ihl.mode === 'manual') {
    const ihlErr = validateUintRange(layer.ihl.value, IPV4_MAX_IHL, 'IHL');
    if (ihlErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'ihl', message: ihlErr });
    } else {
      ihlValue = layer.ihl.value;
      if (ihlValue < IPV4_DEFAULT_IHL) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'ihl',
          message: `Manual IHL (${ihlValue}) is smaller than the minimum of 5 (RFC 791).`,
        });
      }
    }
  }

  const actualTotalLength = IPV4_HEADER_LENGTH + ctx.upperBytesLength;
  if (actualTotalLength > 0xffff) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'totalLength',
      message: `IPv4 total length exceeds the 65535-byte limit (got ${actualTotalLength} bytes).`,
    });
  }

  let totalLengthValue = actualTotalLength;
  if (layer.totalLength.mode === 'manual') {
    const lenErr = validateUintRange(layer.totalLength.value, 0xffff, 'Total Length');
    if (lenErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'totalLength', message: lenErr });
    } else {
      totalLengthValue = layer.totalLength.value;
      if (actualTotalLength <= 0xffff && totalLengthValue !== actualTotalLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'totalLength',
          message: `Using manual Total Length ${totalLengthValue} (actual packet length is ${actualTotalLength} bytes).`,
        });
      }
    }
  }

  const inferredProtocol = protocolForUpperLayer(ctx.upperLayerType);
  const autoProtocol = inferredProtocol ?? 0;
  let protocolValue = autoProtocol;

  if (layer.protocol.mode === 'manual') {
    const protoErr = validateUintRange(layer.protocol.value, 0xff, 'Protocol');
    if (protoErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocol', message: protoErr });
    } else {
      protocolValue = layer.protocol.value;
      if (inferredProtocol !== null && protocolValue !== inferredProtocol) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'protocol',
          message: `Using manual Protocol ${protocolValue} (expected ${inferredProtocol} for the upper layer).`,
        });
      }
    }
  } else if (inferredProtocol === null) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'protocol',
      message: 'No TCP / IPv4 / IPv6 upper layer found; defaulting Protocol to 0.',
    });
  }

  if (errors.length > 0 || !srcIpResult.ok || !dstIpResult.ok) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(IPV4_HEADER_LENGTH);
  header[0] = ((IPV4_VERSION & 0x0f) << 4) | (ihlValue & 0x0f);
  header[1] = layer.tos;
  writeUint16BE(header, 2, totalLengthValue);
  writeUint16BE(header, 4, layer.identification);
  const flagsBits =
    (layer.flags.reserved ? 0x04 : 0) |
    (layer.flags.df ? 0x02 : 0) |
    (layer.flags.mf ? 0x01 : 0);
  writeUint16BE(header, 6, (flagsBits << 13) | (layer.fragmentOffset & 0x1fff));
  header[8] = layer.ttl;
  header[9] = protocolValue;
  header[10] = 0;
  header[11] = 0;
  header.set(srcIpResult.value, 12);
  header.set(dstIpResult.value, 16);

  const autoChecksum = internetChecksum(header);
  let checksumValue = autoChecksum;

  if (layer.headerChecksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.headerChecksum.value, 0xffff, 'Header Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'headerChecksum', message: csumErr });
      return { ok: false, errors, warnings };
    }
    checksumValue = layer.headerChecksum.value;
    if (checksumValue !== autoChecksum) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'headerChecksum',
        message: `Manual Header Checksum 0x${checksumValue.toString(16).padStart(4, '0')} differs from computed 0x${autoChecksum.toString(16).padStart(4, '0')}.`,
      });
    }
  }

  writeUint16BE(header, 10, checksumValue);

  return {
    ok: true,
    bytes: header,
    spans: IPV4_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      ihl: IPV4_DEFAULT_IHL,
      totalLength: actualTotalLength,
      protocol: autoProtocol,
      headerChecksum: autoChecksum,
    },
  };
}
