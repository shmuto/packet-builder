import { concatBytes, readUint16BE, writeUint16BE } from '../../bytes';
import { ipv4PseudoHeaderChecksum, ipv6PseudoHeaderChecksum } from '../../checksum';
import { ok, type Result } from '../../result';
import { computePseudoChecksum } from '../decodeHelpers';
import type {
  FieldDoc,
  IPPseudoContext,
  LayerDefinition,
  ProtocolTables,
} from '../definition';
import {
  expectNumber,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import { getDefaultProtocolTables } from '../registry';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
  type UDPLayer,
} from '../types';

export type { IPPseudoContext };

/** UDP header length (8 bytes, RFC 768) */
export const UDP_HEADER_LENGTH = 8;
export const UDP_MAX_LENGTH = 0xffff;
/** IANA IP Protocol / IPv6 Next Header number for UDP (RFC 768) */
export const IP_PROTOCOL_UDP = 17;

export const UDP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'srcPort', label: 'Source Port', bitOffset: 0, bitLength: 16 },
  { fieldId: 'dstPort', label: 'Destination Port', bitOffset: 16, bitLength: 16 },
  { fieldId: 'length', label: 'Length', bitOffset: 32, bitLength: 16 },
  { fieldId: 'checksum', label: 'Checksum', bitOffset: 48, bitLength: 16 },
];

export const UDP_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  srcPort: {
    summary:
      '16-bit port number of the sending process, typically an ephemeral port (49152-65535). May be 0 when no reply is needed.',
    reference: 'RFC 768 "Fields"',
  },
  dstPort: {
    summary:
      '16-bit port number identifying the target service on the destination host, such as 53 (DNS) or 443 (QUIC).',
    reference: 'RFC 768 "Fields"',
  },
  length: {
    summary:
      'Length in bytes of the UDP header (8 bytes) plus its payload. Minimum valid value is 8.',
    reference: 'RFC 768 "Fields"',
  },
  checksum: {
    summary:
      '16-bit checksum over the IPv4/IPv6 pseudo-header, UDP header, and payload. A computed zero is sent as 0xffff; 0x0000 disables the checksum over IPv4, while IPv6 normally requires a non-zero checksum (except for specific tunnel protocols permitted under RFC 6935 / RFC 6936).',
    reference: 'RFC 768 "Fields" / RFC 8200 §8.1 / RFC 6935',
  },
};

export interface EncodeUDPContext {
  readonly layerIndex: number;
  readonly upperLayerType?: string | null;
  readonly upperBytes: Uint8Array;
  /** Immediately preceding IPv4 or IPv6 layer state used for pseudo-header checksum calculation */
  readonly ip: IPPseudoContext;
  readonly tables?: ProtocolTables;
}

export function createDefaultUDP(): UDPLayer {
  return {
    type: 'udp',
    srcPort: 12345,
    dstPort: 8080,
    length: autoValue(),
    checksum: autoValue(),
  };
}

/**
 * Encodes an 8-byte UDP header (RFC 768 / RFC 8200 §8.1).
 * Converts a computed checksum of 0x0000 to 0xffff per RFC 768 and RFC 8200 §8.1.
 */
export function encodeUDP(layer: UDPLayer, ctx: EncodeUDPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];
  const tables = ctx.tables ?? getDefaultProtocolTables();

  const srcPortErr = validateUintRange(layer.srcPort, 0xffff, 'Source Port');
  if (srcPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcPort', message: srcPortErr });
  }

  const dstPortErr = validateUintRange(layer.dstPort, 0xffff, 'Destination Port');
  if (dstPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstPort', message: dstPortErr });
  }

  const actualLength = UDP_HEADER_LENGTH + ctx.upperBytes.length;
  if (actualLength > UDP_MAX_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'length',
      message: `UDP length exceeds the 65535-byte limit (got ${actualLength} bytes, RFC 768).`,
    });
  }

  let lengthValue = actualLength;
  if (layer.length.mode === 'manual') {
    const lenErr = validateUintRange(layer.length.value, 0xffff, 'UDP Length');
    if (lenErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'length', message: lenErr });
    } else {
      lengthValue = layer.length.value;
      if (lengthValue < UDP_HEADER_LENGTH) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `Manual UDP Length (${lengthValue}) is smaller than the 8-byte minimum (RFC 768).`,
        });
      } else if (actualLength <= UDP_MAX_LENGTH && lengthValue !== actualLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'length',
          message: `Using manual UDP Length ${lengthValue} (actual length is ${actualLength} bytes).`,
        });
      }
    }
  }

  if (layer.checksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.checksum.value, 0xffff, 'UDP Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumErr });
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(UDP_HEADER_LENGTH);
  writeUint16BE(header, 0, layer.srcPort);
  writeUint16BE(header, 2, layer.dstPort);
  writeUint16BE(header, 4, lengthValue);
  header[6] = 0;
  header[7] = 0;

  let autoChecksum = 0;
  if (ctx.ip.status === 'valid') {
    const segment = concatBytes(header, ctx.upperBytes);
    const csumResult =
      ctx.ip.version === 4
        ? ipv4PseudoHeaderChecksum({
            srcIp: ctx.ip.srcIp,
            dstIp: ctx.ip.dstIp,
            protocol: IP_PROTOCOL_UDP,
            segment,
          })
        : ipv6PseudoHeaderChecksum({
            srcIp: ctx.ip.srcIp,
            dstIp: ctx.ip.dstIp,
            nextHeader: IP_PROTOCOL_UDP,
            segment,
          });
    if (!csumResult.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumResult.error });
      return { ok: false, errors, warnings };
    }
    // RFC 768 / RFC 8200 §8.1: transmit all-ones (0xffff) when computed checksum is zero
    autoChecksum = csumResult.value === 0 ? 0xffff : csumResult.value;
  } else if (ctx.ip.status === 'absent' && layer.checksum.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: 'No underlying IPv4 or IPv6 layer for pseudo-header; setting UDP Checksum to 0x0000 (unused).',
    });
  }

  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 6, checksumValue);

  if (layer.checksum.mode === 'manual' && ctx.ip.status === 'valid') {
    if (checksumValue === 0) {
      if (ctx.ip.version === 6) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'checksum',
          message:
            'UDP Checksum is mandatory over IPv6; packets with a 0x0000 checksum must be discarded by receivers (RFC 8200 §8.1).',
        });
      } else if (!tables.allowsZeroUdpChecksumOverIPv4(ctx.upperLayerType ?? null)) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'checksum',
          message: 'UDP Checksum is set to 0x0000 (checksum disabled / unused per RFC 768).',
        });
      }
    } else if (checksumValue !== autoChecksum) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'checksum',
        message: `Using manual UDP Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
      });
    }
  }

  return {
    ok: true,
    bytes: header,
    spans: UDP_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      length: actualLength,
      checksum: autoChecksum,
    },
  };
}

function validateUDPPermalink(raw: Record<string, unknown>, ctx: string): Result<UDPLayer> {
  const checked = validateExactKeys(raw, ['type', 'srcPort', 'dstPort', 'length', 'checksum'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const srcPort = expectNumber(obj, 'srcPort', ctx);
  if (!srcPort.ok) return srcPort;
  const dstPort = expectNumber(obj, 'dstPort', ctx);
  if (!dstPort.ok) return dstPort;
  const length = validateAutoOrManualNumber(obj.length, `${ctx}.length`);
  if (!length.ok) return length;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  return ok({
    type: 'udp',
    srcPort: srcPort.value,
    dstPort: dstPort.value,
    length: length.value,
    checksum: checksum.value,
  });
}

export const udpDefinition: LayerDefinition<UDPLayer, 'udp'> = {
  type: 'udp',
  minHeaderLength: UDP_HEADER_LENGTH,
  createDefault: createDefaultUDP,
  headerLength: () => UDP_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeUDP(layer, {
      layerIndex: ctx.layerIndex,
      upperLayerType: ctx.upperLayerType,
      upperBytes: ctx.upperBytes,
      ip: ctx.ip,
      tables: ctx.tables,
    }),
  provideLowerContext(layer) {
    if (
      Number.isInteger(layer.srcPort) &&
      layer.srcPort >= 0 &&
      layer.srcPort <= 0xffff &&
      Number.isInteger(layer.dstPort) &&
      layer.dstPort >= 0 &&
      layer.dstPort <= 0xffff
    ) {
      return { udp: { status: 'valid', srcPort: layer.srcPort, dstPort: layer.dstPort } };
    }
    return { udp: { status: 'invalid' } };
  },
  decode(bytes, offset, ctx) {
    const srcPort = readUint16BE(bytes, offset);
    const dstPort = readUint16BE(bytes, offset + 2);
    const length = readUint16BE(bytes, offset + 4);
    const checksum = readUint16BE(bytes, offset + 6);

    const actualLength = bytes.length - offset;
    const segmentCopy = new Uint8Array(bytes.subarray(offset));
    segmentCopy[6] = 0;
    segmentCopy[7] = 0;

    const expectedChecksum = ctx.ip
      ? (() => {
          const csumRes = computePseudoChecksum(ctx.ip, IP_PROTOCOL_UDP, segmentCopy);
          return csumRes.ok ? (csumRes.value === 0 ? 0xffff : csumRes.value) : null;
        })()
      : null;

    const udpLayer: UDPLayer = {
      type: 'udp',
      srcPort,
      dstPort,
      length: length === actualLength ? autoValue() : manualValue(length),
      checksum:
        expectedChecksum !== null && checksum === expectedChecksum
          ? autoValue()
          : manualValue(checksum),
    };

    const payloadOffset = offset + UDP_HEADER_LENGTH;
    const upper = ctx.decodeByUdpPort(bytes, payloadOffset, dstPort, ctx.tunnelDepth);
    return {
      layers: [udpLayer, ...upper.layers],
      payload: upper.payload,
    };
  },
  validatePermalink: validateUDPPermalink,
  fieldDocs: UDP_FIELD_DOCS,
  protocols: {
    ipProtocol: IP_PROTOCOL_UDP,
  },
};
