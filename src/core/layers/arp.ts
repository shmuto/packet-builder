import { parseIPv4, parseMac, writeUint16BE } from '../bytes';
import type {
  ARPLayer,
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** ARP packet length for IPv4 over Ethernet (28 bytes / 224 bits, RFC 826) */
export const ARP_HEADER_LENGTH = 28;

export const ARP_HTYPE_ETHERNET = 1;
export const ARP_PTYPE_IPV4 = 0x0800;
export const ARP_HLEN_ETHERNET = 6;
export const ARP_PLEN_IPV4 = 4;
export const ARP_OP_REQUEST = 1;
export const ARP_OP_REPLY = 2;

export const ARP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'hardwareType', label: 'Hardware Type', bitOffset: 0, bitLength: 16 },
  { fieldId: 'protocolType', label: 'Protocol Type', bitOffset: 16, bitLength: 16 },
  { fieldId: 'hardwareLength', label: 'Hardware Size', bitOffset: 32, bitLength: 8 },
  { fieldId: 'protocolLength', label: 'Protocol Size', bitOffset: 40, bitLength: 8 },
  { fieldId: 'operation', label: 'Operation', bitOffset: 48, bitLength: 16 },
  { fieldId: 'senderMac', label: 'Sender MAC', bitOffset: 64, bitLength: 48 },
  { fieldId: 'senderIp', label: 'Sender IPv4', bitOffset: 112, bitLength: 32 },
  { fieldId: 'targetMac', label: 'Target MAC', bitOffset: 144, bitLength: 48 },
  { fieldId: 'targetIp', label: 'Target IPv4', bitOffset: 192, bitLength: 32 },
];

export interface EncodeARPContext {
  readonly layerIndex: number;
}

/**
 * Encodes a 28-byte IPv4-over-Ethernet ARP packet (RFC 826).
 */
export function encodeARP(layer: ARPLayer, ctx: EncodeARPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  let hardwareType = ARP_HTYPE_ETHERNET;
  if (layer.hardwareType.mode === 'manual') {
    const err = validateUintRange(layer.hardwareType.value, 0xffff, 'Hardware Type');
    if (err !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'hardwareType', message: err });
    } else {
      hardwareType = layer.hardwareType.value;
      if (hardwareType !== ARP_HTYPE_ETHERNET) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'hardwareType',
          message: `Using manual Hardware Type ${hardwareType} (Ethernet is 1 per RFC 826).`,
        });
      }
    }
  }

  let protocolType = ARP_PTYPE_IPV4;
  if (layer.protocolType.mode === 'manual') {
    const err = validateUintRange(layer.protocolType.value, 0xffff, 'Protocol Type');
    if (err !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocolType', message: err });
    } else {
      protocolType = layer.protocolType.value;
      if (protocolType !== ARP_PTYPE_IPV4) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'protocolType',
          message: `Using manual Protocol Type 0x${protocolType.toString(16).padStart(4, '0')} (IPv4 is 0x0800 per RFC 826).`,
        });
      }
    }
  }

  let hardwareLength = ARP_HLEN_ETHERNET;
  if (layer.hardwareLength.mode === 'manual') {
    const err = validateUintRange(layer.hardwareLength.value, 0xff, 'Hardware Size');
    if (err !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'hardwareLength', message: err });
    } else {
      hardwareLength = layer.hardwareLength.value;
      if (hardwareLength !== ARP_HLEN_ETHERNET) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'hardwareLength',
          message: `Using manual Hardware Size ${hardwareLength} (MAC addresses are 6 bytes).`,
        });
      }
    }
  }

  let protocolLength = ARP_PLEN_IPV4;
  if (layer.protocolLength.mode === 'manual') {
    const err = validateUintRange(layer.protocolLength.value, 0xff, 'Protocol Size');
    if (err !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocolLength', message: err });
    } else {
      protocolLength = layer.protocolLength.value;
      if (protocolLength !== ARP_PLEN_IPV4) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'protocolLength',
          message: `Using manual Protocol Size ${protocolLength} (IPv4 addresses are 4 bytes).`,
        });
      }
    }
  }

  const opErr = validateUintRange(layer.operation, 0xffff, 'Operation');
  if (opErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'operation', message: opErr });
  } else if (layer.operation !== ARP_OP_REQUEST && layer.operation !== ARP_OP_REPLY) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'operation',
      message: `Operation ${layer.operation} is non-standard for basic ARP (RFC 826 defines 1=Request, 2=Reply).`,
    });
  }

  const senderMac = parseMac(layer.senderMac);
  if (!senderMac.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'senderMac', message: senderMac.error });
  }

  const senderIp = parseIPv4(layer.senderIp);
  if (!senderIp.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'senderIp', message: senderIp.error });
  }

  const targetMac = parseMac(layer.targetMac);
  if (!targetMac.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'targetMac', message: targetMac.error });
  }

  const targetIp = parseIPv4(layer.targetIp);
  if (!targetIp.ok) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'targetIp', message: targetIp.error });
  }

  if (
    errors.length > 0 ||
    !senderMac.ok ||
    !senderIp.ok ||
    !targetMac.ok ||
    !targetIp.ok
  ) {
    return { ok: false, errors, warnings };
  }

  const packet = new Uint8Array(ARP_HEADER_LENGTH);
  writeUint16BE(packet, 0, hardwareType);
  writeUint16BE(packet, 2, protocolType);
  packet[4] = hardwareLength;
  packet[5] = protocolLength;
  writeUint16BE(packet, 6, layer.operation);
  packet.set(senderMac.value, 8);
  packet.set(senderIp.value, 14);
  packet.set(targetMac.value, 18);
  packet.set(targetIp.value, 24);

  return {
    ok: true,
    bytes: packet,
    spans: ARP_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      hardwareType: ARP_HTYPE_ETHERNET,
      protocolType: ARP_PTYPE_IPV4,
      hardwareLength: ARP_HLEN_ETHERNET,
      protocolLength: ARP_PLEN_IPV4,
    },
  };
}
