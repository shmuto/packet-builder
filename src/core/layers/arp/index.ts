import {
  formatIPv4,
  formatMac,
  parseIPv4,
  parseMac,
  readUint16BE,
  writeUint16BE,
} from '../../bytes';
import { ok, type Result } from '../../result';
import type { FieldDoc, LayerDefinition } from '../definition';
import {
  expectNumber,
  expectString,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type ARPLayer,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

/** ARP packet length for IPv4 over Ethernet (28 bytes / 224 bits, RFC 826) */
export const ARP_HEADER_LENGTH = 28;
/** EtherType for ARP (RFC 826) */
export const ETHERTYPE_ARP = 0x0806;

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

export const ARP_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  hardwareType: {
    summary:
      '16-bit code identifying the link-layer hardware type. Value 1 denotes Ethernet.',
    reference: 'RFC 826 "Packet format"',
  },
  protocolType: {
    summary:
      '16-bit code identifying the network-layer protocol being resolved, using EtherType values. Value 0x0800 denotes IPv4.',
    reference: 'RFC 826 "Packet format"',
  },
  hardwareLength: {
    summary:
      'Length in octets of each hardware address in this ARP message. Ethernet MAC addresses are 6 bytes.',
    reference: 'RFC 826 "Packet format"',
  },
  protocolLength: {
    summary:
      'Length in octets of each protocol address in this ARP message. IPv4 addresses are 4 bytes.',
    reference: 'RFC 826 "Packet format"',
  },
  operation: {
    summary:
      'Specifies the ARP action being performed: 1 for Request (asking for a MAC address) and 2 for Reply.',
    reference: 'RFC 826 "Packet format"',
  },
  senderMac: {
    summary:
      'Hardware (MAC) address of the host sending this ARP request or reply.',
    reference: 'RFC 826 "Packet format"',
  },
  senderIp: {
    summary:
      'IPv4 address of the host sending this ARP message.',
    reference: 'RFC 826 "Packet format"',
  },
  targetMac: {
    summary:
      'Hardware (MAC) address of the intended target. Usually set to 00:00:00:00:00:00 in requests (ignored by receivers; RFC 5227 §2.1.1 recommends all zeros for ARP Probes).',
    reference: 'RFC 826 "Packet format" / RFC 5227 §2.1.1',
  },
  targetIp: {
    summary:
      'IPv4 address of the host whose MAC address is being queried (in a request) or answered (in a reply).',
    reference: 'RFC 826 "Packet format"',
  },
};

export interface EncodeARPContext {
  readonly layerIndex: number;
}

export function createDefaultARP(): ARPLayer {
  return {
    type: 'arp',
    hardwareType: autoValue(),
    protocolType: autoValue(),
    hardwareLength: autoValue(),
    protocolLength: autoValue(),
    operation: 1,
    senderMac: '66:77:88:99:aa:bb',
    senderIp: '192.168.0.1',
    targetMac: '00:00:00:00:00:00',
    targetIp: '192.168.0.2',
  };
}

/**
 * Encodes a 28-byte IPv4-over-Ethernet ARP packet (RFC 826).
 */
export function encodeARP(layer: ARPLayer, ctx: EncodeARPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  let hardwareType = ARP_HTYPE_ETHERNET;
  if (layer.hardwareType.mode === 'manual') {
    const rangeErr = validateUintRange(layer.hardwareType.value, 0xffff, 'Hardware Type');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'hardwareType', message: rangeErr });
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
    const rangeErr = validateUintRange(layer.protocolType.value, 0xffff, 'Protocol Type');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocolType', message: rangeErr });
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
    const rangeErr = validateUintRange(layer.hardwareLength.value, 0xff, 'Hardware Size');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'hardwareLength', message: rangeErr });
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
    const rangeErr = validateUintRange(layer.protocolLength.value, 0xff, 'Protocol Size');
    if (rangeErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'protocolLength', message: rangeErr });
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

function validateARPPermalink(raw: Record<string, unknown>, ctx: string): Result<ARPLayer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'hardwareType',
      'protocolType',
      'hardwareLength',
      'protocolLength',
      'operation',
      'senderMac',
      'senderIp',
      'targetMac',
      'targetIp',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const hardwareType = validateAutoOrManualNumber(obj.hardwareType, `${ctx}.hardwareType`);
  if (!hardwareType.ok) return hardwareType;
  const protocolType = validateAutoOrManualNumber(obj.protocolType, `${ctx}.protocolType`);
  if (!protocolType.ok) return protocolType;
  const hardwareLength = validateAutoOrManualNumber(obj.hardwareLength, `${ctx}.hardwareLength`);
  if (!hardwareLength.ok) return hardwareLength;
  const protocolLength = validateAutoOrManualNumber(obj.protocolLength, `${ctx}.protocolLength`);
  if (!protocolLength.ok) return protocolLength;
  const operation = expectNumber(obj, 'operation', ctx);
  if (!operation.ok) return operation;
  const senderMac = expectString(obj, 'senderMac', ctx);
  if (!senderMac.ok) return senderMac;
  const senderIp = expectString(obj, 'senderIp', ctx);
  if (!senderIp.ok) return senderIp;
  const targetMac = expectString(obj, 'targetMac', ctx);
  if (!targetMac.ok) return targetMac;
  const targetIp = expectString(obj, 'targetIp', ctx);
  if (!targetIp.ok) return targetIp;
  return ok({
    type: 'arp',
    hardwareType: hardwareType.value,
    protocolType: protocolType.value,
    hardwareLength: hardwareLength.value,
    protocolLength: protocolLength.value,
    operation: operation.value,
    senderMac: senderMac.value,
    senderIp: senderIp.value,
    targetMac: targetMac.value,
    targetIp: targetIp.value,
  });
}

export const arpDefinition: LayerDefinition<ARPLayer, 'arp'> = {
  type: 'arp',
  minHeaderLength: ARP_HEADER_LENGTH,
  createDefault: createDefaultARP,
  headerLength: () => ARP_HEADER_LENGTH,
  encode: (layer, ctx) => encodeARP(layer, { layerIndex: ctx.layerIndex }),
  decode(bytes, offset, ctx) {
    const remaining = bytes.length - offset;
    if (remaining < ARP_HEADER_LENGTH) {
      ctx.notes.push(
        `ARP packet after ${ctx.enclosingLabel} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return null;
    }

    const htype = readUint16BE(bytes, offset);
    const ptype = readUint16BE(bytes, offset + 2);
    const hlen = bytes[offset + 4];
    const plen = bytes[offset + 5];
    const operation = readUint16BE(bytes, offset + 6);

    const layer: ARPLayer = {
      type: 'arp',
      hardwareType: htype === ARP_HTYPE_ETHERNET ? autoValue() : manualValue(htype),
      protocolType: ptype === ARP_PTYPE_IPV4 ? autoValue() : manualValue(ptype),
      hardwareLength: hlen === ARP_HLEN_ETHERNET ? autoValue() : manualValue(hlen),
      protocolLength: plen === ARP_PLEN_IPV4 ? autoValue() : manualValue(plen),
      operation,
      senderMac: formatMac(bytes.subarray(offset + 8, offset + 14)),
      senderIp: formatIPv4(bytes.subarray(offset + 14, offset + 18)),
      targetMac: formatMac(bytes.subarray(offset + 18, offset + 24)),
      targetIp: formatIPv4(bytes.subarray(offset + 24, offset + 28)),
    };

    const trailing = bytes.slice(offset + ARP_HEADER_LENGTH);
    if (trailing.length > 0) {
      ctx.notes.push(
        `Preserved ${trailing.length} trailing byte(s) after the 28-byte ARP header (e.g., Ethernet padding) in Payload.`,
      );
    }

    return { layers: [layer], payload: trailing };
  },
  validatePermalink: validateARPPermalink,
  fieldDocs: ARP_FIELD_DOCS,
  protocols: {
    etherType: ETHERTYPE_ARP,
    etherTypeLabel: 'ARP',
  },
};
