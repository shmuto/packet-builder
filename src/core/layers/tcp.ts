import { concatBytes, writeUint16BE, writeUint32BE } from '../bytes';
import { ipv4PseudoHeaderChecksum } from '../checksum';
import { IP_PROTOCOL_TCP } from './ipv4';
import type { IPv4PseudoContext } from './udp';
import type {
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
  TCPLayer,
} from './types';
import { validateUintRange } from './types';

/** Base TCP header length without options (20 bytes, RFC 9293 Section 3.1) */
export const TCP_HEADER_LENGTH = 20;
export const TCP_DEFAULT_DATA_OFFSET = 5;

export const TCP_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'srcPort', label: 'Source Port', bitOffset: 0, bitLength: 16 },
  { fieldId: 'dstPort', label: 'Destination Port', bitOffset: 16, bitLength: 16 },
  { fieldId: 'seqNumber', label: 'Sequence Number', bitOffset: 32, bitLength: 32 },
  { fieldId: 'ackNumber', label: 'Acknowledgment Number', bitOffset: 64, bitLength: 32 },
  { fieldId: 'dataOffset', label: 'Data Offset', bitOffset: 96, bitLength: 4 },
  { fieldId: 'reserved', label: 'Reserved (0)', bitOffset: 100, bitLength: 4 },
  { fieldId: 'flags', label: 'Control Bits', bitOffset: 104, bitLength: 8 },
  { fieldId: 'windowSize', label: 'Window Size', bitOffset: 112, bitLength: 16 },
  { fieldId: 'checksum', label: 'Checksum', bitOffset: 128, bitLength: 16 },
  { fieldId: 'urgentPointer', label: 'Urgent Pointer', bitOffset: 144, bitLength: 16 },
];

export interface EncodeTCPContext {
  readonly layerIndex: number;
  readonly upperBytes: Uint8Array;
  /** Underlying IPv4 layer state used for pseudo-header checksum calculation */
  readonly ipv4: IPv4PseudoContext;
}

/**
 * Encodes a 20-byte base TCP header (RFC 9293 Section 3.1).
 * Keeps a computed checksum of 0x0000 as 0x0000 per RFC 9293.
 */
export function encodeTCP(layer: TCPLayer, ctx: EncodeTCPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];

  const srcPortErr = validateUintRange(layer.srcPort, 0xffff, 'Source Port');
  if (srcPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'srcPort', message: srcPortErr });
  }

  const dstPortErr = validateUintRange(layer.dstPort, 0xffff, 'Destination Port');
  if (dstPortErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dstPort', message: dstPortErr });
  }

  const seqErr = validateUintRange(layer.seqNumber, 0xffffffff, 'Sequence Number');
  if (seqErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'seqNumber', message: seqErr });
  }

  const ackErr = validateUintRange(layer.ackNumber, 0xffffffff, 'Acknowledgment Number');
  if (ackErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'ackNumber', message: ackErr });
  }

  let dataOffsetValue = TCP_DEFAULT_DATA_OFFSET;
  if (layer.dataOffset.mode === 'manual') {
    const doErr = validateUintRange(layer.dataOffset.value, 0x0f, 'Data Offset');
    if (doErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'dataOffset', message: doErr });
    } else {
      dataOffsetValue = layer.dataOffset.value;
      if (dataOffsetValue < TCP_DEFAULT_DATA_OFFSET) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'dataOffset',
          message: `Manual Data Offset (${dataOffsetValue}) is smaller than the minimum of 5 (RFC 9293).`,
        });
      } else if (dataOffsetValue !== TCP_DEFAULT_DATA_OFFSET) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'dataOffset',
          message: `Using manual Data Offset ${dataOffsetValue} (base header without options is 5).`,
        });
      }
    }
  }

  const winErr = validateUintRange(layer.windowSize, 0xffff, 'Window Size');
  if (winErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'windowSize', message: winErr });
  }

  const urgErr = validateUintRange(layer.urgentPointer, 0xffff, 'Urgent Pointer');
  if (urgErr !== null) {
    errors.push({ layerIndex: ctx.layerIndex, fieldId: 'urgentPointer', message: urgErr });
  }

  if (layer.checksum.mode === 'manual') {
    const csumErr = validateUintRange(layer.checksum.value, 0xffff, 'TCP Checksum');
    if (csumErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumErr });
    }
  }

  const segmentLength = TCP_HEADER_LENGTH + ctx.upperBytes.length;
  if (segmentLength > 0xffff) {
    errors.push({
      layerIndex: ctx.layerIndex,
      message: `TCP segment length exceeds the 65535-byte limit (got ${segmentLength} bytes).`,
    });
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(TCP_HEADER_LENGTH);
  writeUint16BE(header, 0, layer.srcPort);
  writeUint16BE(header, 2, layer.dstPort);
  writeUint32BE(header, 4, layer.seqNumber);
  writeUint32BE(header, 8, layer.ackNumber);
  header[12] = (dataOffsetValue & 0x0f) << 4;
  const flagsByte =
    (layer.flags.cwr ? 0x80 : 0) |
    (layer.flags.ece ? 0x40 : 0) |
    (layer.flags.urg ? 0x20 : 0) |
    (layer.flags.ack ? 0x10 : 0) |
    (layer.flags.psh ? 0x08 : 0) |
    (layer.flags.rst ? 0x04 : 0) |
    (layer.flags.syn ? 0x02 : 0) |
    (layer.flags.fin ? 0x01 : 0);
  header[13] = flagsByte;
  writeUint16BE(header, 14, layer.windowSize);
  header[16] = 0;
  header[17] = 0;
  writeUint16BE(header, 18, layer.urgentPointer);

  let autoChecksum = 0;
  if (ctx.ipv4.status === 'valid') {
    const segment = concatBytes(header, ctx.upperBytes);
    const csumResult = ipv4PseudoHeaderChecksum({
      srcIp: ctx.ipv4.srcIp,
      dstIp: ctx.ipv4.dstIp,
      protocol: IP_PROTOCOL_TCP,
      segment,
    });
    if (!csumResult.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumResult.error });
      return { ok: false, errors, warnings };
    }
    autoChecksum = csumResult.value;
  } else if (ctx.ipv4.status === 'absent' && layer.checksum.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: 'No underlying IPv4 layer for pseudo-header; setting TCP Checksum to 0x0000.',
    });
  }

  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 16, checksumValue);

  if (
    layer.checksum.mode === 'manual' &&
    ctx.ipv4.status === 'valid' &&
    checksumValue !== autoChecksum
  ) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: `Using manual TCP Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
    });
  }

  return {
    ok: true,
    bytes: header,
    spans: TCP_FIELD_SPANS,
    warnings,
    resolvedAutoValues: {
      dataOffset: TCP_DEFAULT_DATA_OFFSET,
      checksum: autoChecksum,
    },
  };
}
