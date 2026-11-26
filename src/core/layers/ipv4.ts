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

/** IPv4 header length without options (IHL=5 fixed, 20 bytes) */
export const IPV4_HEADER_LENGTH = 20;
export const IPV4_VERSION = 4;
export const IPV4_IHL = 5;
export const IPV4_MAX_TOTAL_LENGTH = 0xffff;

/** IPv4 protocol numbers (IANA / RFC 792, 2003, 9293, 768) */
export const IP_PROTOCOL_ICMP = 1;
export const IP_PROTOCOL_IPIP = 4;
export const IP_PROTOCOL_TCP = 6;
export const IP_PROTOCOL_UDP = 17;

export const IPV4_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'version', label: 'Version (4)', bitOffset: 0, bitLength: 4 },
  { fieldId: 'ihl', label: 'IHL (5)', bitOffset: 4, bitLength: 4 },
  { fieldId: 'tos', label: 'TOS (DSCP/ECN)', bitOffset: 8, bitLength: 8 },
  { fieldId: 'totalLength', label: 'Total Length', bitOffset: 16, bitLength: 16 },
  { fieldId: 'identification', label: 'Identification', bitOffset: 32, bitLength: 16 },
  { fieldId: 'flags', label: 'Flags (R/DF/MF)', bitOffset: 48, bitLength: 3 },
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

function protocolNumberForUpperLayer(upperLayerType: LayerType | null): number | null {
  switch (upperLayerType) {
    case 'icmp':
      return IP_PROTOCOL_ICMP;
    case 'ipv4':
      return IP_PROTOCOL_IPIP;
    case 'tcp':
      return IP_PROTOCOL_TCP;
    case 'udp':
      return IP_PROTOCOL_UDP;
    default:
      return null;
  }
}

/**
 * Encodes an IPv4 header without options (20 bytes, IHL=5, RFC 791).
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

  const srcIpResult = parseIPv4(layer.srcIp);
  if (!srcIpResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcIp', message: srcIpResult.error });
  }

  const dstIpResult = parseIPv4(layer.dstIp);
  if (!dstIpResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstIp', message: dstIpResult.error });
  }

  // RFC 791 Section 3.1: Total Length is 16-bit (max 65535 bytes)
  const actualTotalLength = IPV4_HEADER_LENGTH + ctx.upperBytesLength;
  if (actualTotalLength > IPV4_MAX_TOTAL_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'totalLength',
      message: `IPv4 total length exceeds the 65535-byte limit (got ${actualTotalLength} bytes, RFC 791).`,
    });
  }

  let totalLengthValue = actualTotalLength;
  if (layer.totalLength.mode === 'manual') {
    const totalLenErr = validateUintRange(layer.totalLength.value, 0xffff, 'Total Length');
    if (totalLenErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'totalLength', message: totalLenErr });
    } else {
      totalLengthValue = layer.totalLength.value;
      if (totalLengthValue < IPV4_HEADER_LENGTH) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'totalLength',
          message: `Manual Total Length (${totalLengthValue}) is smaller than the 20-byte IPv4 header (RFC 791).`,
        });
      } else if (actualTotalLength <= IPV4_MAX_TOTAL_LENGTH && totalLengthValue !== actualTotalLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'totalLength',
          message: `Using manual Total Length ${totalLengthValue} (actual packet length is ${actualTotalLength} bytes).`,
        });
      }
    }
  }

  const inferredProtocol = protocolNumberForUpperLayer(ctx.upperLayerType);
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
      message: 'No ICMP / IPv4 / TCP / UDP upper layer found; defaulting Protocol to 0.',
    });
  }

  if (layer.headerChecksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.headerChecksum.value, 0xffff, 'Header Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'headerChecksum', message: csumErr });
    }
  }

  if (layer.flags.reserved) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'flags',
      message: 'IPv4 Reserved flag bit is set to 1 (must be 0 per RFC 791 Section 3.1).',
    });
  }

  if (errors.length > 0 || !srcIpResult.ok || !dstIpResult.ok) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(IPV4_HEADER_LENGTH);
  header[0] = (IPV4_VERSION << 4) | IPV4_IHL;
  header[1] = layer.tos;
  writeUint16BE(header, 2, totalLengthValue);
  writeUint16BE(header, 4, layer.identification);
  const flagsBits =
    (layer.flags.reserved ? 0b100 : 0) |
    (layer.flags.df ? 0b010 : 0) |
    (layer.flags.mf ? 0b001 : 0);
  writeUint16BE(header, 6, (flagsBits << 13) | layer.fragmentOffset);
  header[8] = layer.ttl;
  header[9] = protocolValue;
  header[10] = 0;
  header[11] = 0;
  header.set(srcIpResult.value, 12);
  header.set(dstIpResult.value, 16);

  const autoChecksum = internetChecksum(header);
  const checksumValue =
    layer.headerChecksum.mode === 'manual' ? layer.headerChecksum.value : autoChecksum;
  writeUint16BE(header, 10, checksumValue);

  if (layer.headerChecksum.mode === 'manual' && checksumValue !== autoChecksum) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'headerChecksum',
      message: `Using manual Header Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
    });
  }

  return {
    ok: true,
    bytes: header,
    spans: IPV4_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      totalLength: actualTotalLength,
      protocol: autoProtocol,
      headerChecksum: autoChecksum,
    },
  };
}
