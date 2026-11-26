import { parseIPv6, writeUint16BE, writeUint32BE } from '../bytes';
import {
  IP_PROTOCOL_IPIP,
  IP_PROTOCOL_IPV6,
  IP_PROTOCOL_TCP,
  IP_PROTOCOL_UDP,
} from './ipv4';
import type {
  IPv6Layer,
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** Fixed IPv6 header length without extension headers (40 bytes, RFC 8200 §3) */
export const IPV6_HEADER_LENGTH = 40;
export const IPV6_VERSION = 6;
export const IPV6_MAX_FLOW_LABEL = 0xfffff;
export const IPV6_MAX_PAYLOAD_LENGTH = 0xffff;

export const IPV6_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'version', label: 'Version (6)', bitOffset: 0, bitLength: 4 },
  { fieldId: 'trafficClass', label: 'Traffic Class', bitOffset: 4, bitLength: 8 },
  { fieldId: 'flowLabel', label: 'Flow Label', bitOffset: 12, bitLength: 20 },
  { fieldId: 'payloadLength', label: 'Payload Length', bitOffset: 32, bitLength: 16 },
  { fieldId: 'nextHeader', label: 'Next Header', bitOffset: 48, bitLength: 8 },
  { fieldId: 'hopLimit', label: 'Hop Limit', bitOffset: 56, bitLength: 8 },
  { fieldId: 'srcIp', label: 'Source IPv6', bitOffset: 64, bitLength: 128 },
  { fieldId: 'dstIp', label: 'Destination IPv6', bitOffset: 192, bitLength: 128 },
];

export interface EncodeIPv6Context {
  readonly layerIndex: number;
  readonly upperLayerType: LayerType | null;
  readonly upperBytesLength: number;
}

function nextHeaderForUpperLayer(upperLayerType: LayerType | null): number | null {
  switch (upperLayerType) {
    case 'tcp':
      return IP_PROTOCOL_TCP;
    case 'udp':
      return IP_PROTOCOL_UDP;
    case 'ipv4':
      return IP_PROTOCOL_IPIP;
    case 'ipv6':
      return IP_PROTOCOL_IPV6;
    default:
      return null;
  }
}

/**
 * Encodes a 40-byte fixed IPv6 header (RFC 8200 §3, no extension headers).
 */
export function encodeIPv6(layer: IPv6Layer, ctx: EncodeIPv6Context): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const tcErr = validateUintRange(layer.trafficClass, 0xff, 'Traffic Class');
  if (tcErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'trafficClass', message: tcErr });
  }

  const flowErr = validateUintRange(layer.flowLabel, IPV6_MAX_FLOW_LABEL, 'Flow Label');
  if (flowErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'flowLabel', message: flowErr });
  }

  const hopErr = validateUintRange(layer.hopLimit, 0xff, 'Hop Limit');
  if (hopErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'hopLimit', message: hopErr });
  }

  const srcIpResult = parseIPv6(layer.srcIp);
  if (!srcIpResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcIp', message: srcIpResult.error });
  }

  const dstIpResult = parseIPv6(layer.dstIp);
  if (!dstIpResult.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstIp', message: dstIpResult.error });
  }

  // RFC 8200 §3: Payload Length is 16-bit (max 65535 bytes; jumbograms RFC 2675 out of scope)
  const actualPayloadLength = ctx.upperBytesLength;
  if (actualPayloadLength > IPV6_MAX_PAYLOAD_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'payloadLength',
      message: `IPv6 payload length exceeds the 65535-byte limit (got ${actualPayloadLength} bytes, RFC 8200 §3).`,
    });
  }

  let payloadLengthValue = actualPayloadLength;
  if (layer.payloadLength.mode === 'manual') {
    const lenErr = validateUintRange(layer.payloadLength.value, 0xffff, 'Payload Length');
    if (lenErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'payloadLength', message: lenErr });
    } else {
      payloadLengthValue = layer.payloadLength.value;
      if (
        actualPayloadLength <= IPV6_MAX_PAYLOAD_LENGTH &&
        payloadLengthValue !== actualPayloadLength
      ) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'payloadLength',
          message: `Using manual Payload Length ${payloadLengthValue} (actual upper-layer length is ${actualPayloadLength} bytes).`,
        });
      }
    }
  }

  if (ctx.upperLayerType === 'icmp') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'nextHeader',
      message:
        'ICMPv4 sits directly above IPv6; use ICMPv6 (Next Header 58, RFC 4443) for IPv6 packets.',
    });
  }

  const inferredNextHeader = nextHeaderForUpperLayer(ctx.upperLayerType);
  const autoNextHeader = inferredNextHeader ?? 0;
  let nextHeaderValue = autoNextHeader;

  if (layer.nextHeader.mode === 'manual') {
    const nhErr = validateUintRange(layer.nextHeader.value, 0xff, 'Next Header');
    if (nhErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'nextHeader', message: nhErr });
    } else {
      nextHeaderValue = layer.nextHeader.value;
      if (inferredNextHeader !== null && nextHeaderValue !== inferredNextHeader) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'nextHeader',
          message: `Using manual Next Header ${nextHeaderValue} (expected ${inferredNextHeader} for the upper layer).`,
        });
      }
    }
  } else if (inferredNextHeader === null && ctx.upperLayerType !== 'icmp') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'nextHeader',
      message: 'No TCP / UDP / IPv4 / IPv6 upper layer found; defaulting Next Header to 0.',
    });
  }

  if (errors.length > 0 || !srcIpResult.ok || !dstIpResult.ok) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(IPV6_HEADER_LENGTH);
  const firstWord =
    ((IPV6_VERSION << 28) |
      ((layer.trafficClass & 0xff) << 20) |
      (layer.flowLabel & IPV6_MAX_FLOW_LABEL)) >>>
    0;
  writeUint32BE(header, 0, firstWord);
  writeUint16BE(header, 4, payloadLengthValue);
  header[6] = nextHeaderValue;
  header[7] = layer.hopLimit;
  header.set(srcIpResult.value, 8);
  header.set(dstIpResult.value, 24);

  return {
    ok: true,
    bytes: header,
    spans: IPV6_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      payloadLength: actualPayloadLength,
      nextHeader: autoNextHeader,
    },
  };
}
