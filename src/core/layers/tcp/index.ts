import { concatBytes, parseHexBytes, writeUint16BE, writeUint32BE } from '../../bytes';
import { ipv4PseudoHeaderChecksum, ipv6PseudoHeaderChecksum } from '../../checksum';
import type { IPPseudoContext, LayerDefinition } from '../definition';
import {
  autoValue,
  validateUintRange,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
  type TCPLayer,
  type TCPOption,
} from '../types';
import { decodeTCPLayer } from './decode';
import { TCP_FIELD_DOCS } from './fieldDocs';
import { validateTCPPermalink } from './permalink';

/** Base TCP header length without options (20 bytes, RFC 9293 Section 3.1) */
export const TCP_HEADER_LENGTH = 20;
export const TCP_DEFAULT_DATA_OFFSET = 5;
export const TCP_MAX_DATA_OFFSET = 15;
export const TCP_MAX_OPTIONS_LENGTH = (TCP_MAX_DATA_OFFSET - TCP_DEFAULT_DATA_OFFSET) * 4; // 40 bytes
/** IANA IP Protocol / IPv6 Next Header number for TCP (RFC 9293) */
export const IP_PROTOCOL_TCP = 6;

/** Standard TCP Option Kind numbers (IANA / RFC 9293, RFC 7323, RFC 2018) */
export const TCP_OPT_EOL = 0;
export const TCP_OPT_NOP = 1;
export const TCP_OPT_MSS = 2;
export const TCP_OPT_WINDOW_SCALE = 3;
export const TCP_OPT_SACK_PERMITTED = 4;
export const TCP_OPT_SACK = 5;
export const TCP_OPT_TIMESTAMPS = 8;

export const TCP_MAX_WINDOW_SCALE_SHIFT = 14;

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
  /** Immediately preceding IPv4 or IPv6 layer state used for pseudo-header checksum calculation */
  readonly ip: IPPseudoContext;
}

export function createDefaultTCP(): TCPLayer {
  return {
    type: 'tcp',
    srcPort: 54321,
    dstPort: 443,
    seqNumber: 1000,
    ackNumber: 0,
    dataOffset: autoValue(),
    flags: {
      cwr: false,
      ece: false,
      urg: false,
      ack: false,
      psh: false,
      rst: false,
      syn: true,
      fin: false,
    },
    windowSize: 65535,
    checksum: autoValue(),
    urgentPointer: 0,
    options: [],
  };
}

/**
 * Estimates the unpadded byte length of a single TCP option.
 */
export function getTCPOptionByteLength(opt: TCPOption): number {
  switch (opt.kind) {
    case 'eol':
    case 'nop':
      return 1;
    case 'mss':
      return 4;
    case 'windowScale':
      return 3;
    case 'sackPermitted':
      return 2;
    case 'sack':
      return 2 + opt.blocks.length * 8;
    case 'timestamps':
      return 10;
    case 'raw': {
      const parsed = parseHexBytes(opt.dataHex);
      const dataLen = parsed.ok ? parsed.value.length : 0;
      return (opt.length.mode === 'none' ? 1 : 2) + dataLen;
    }
  }
}

/**
 * Computes raw (unpadded) and zero-padded option byte counts for a TCP options list.
 */
export function getTCPOptionsMetrics(options: readonly TCPOption[]): {
  readonly rawBytes: number;
  readonly paddingBytes: number;
  readonly paddedBytes: number;
  readonly dataOffset: number;
} {
  let rawBytes = 0;
  for (const opt of options) {
    rawBytes += getTCPOptionByteLength(opt);
  }
  const paddingBytes = (4 - (rawBytes % 4)) % 4;
  const paddedBytes = rawBytes + paddingBytes;
  const dataOffset = TCP_DEFAULT_DATA_OFFSET + paddedBytes / 4;
  return { rawBytes, paddingBytes, paddedBytes, dataOffset };
}

/**
 * Returns the padded TCP header length in bytes (clamped to 20..60 for error-placeholder sizing).
 */
export function getTCPHeaderLength(layer: TCPLayer): number {
  const { paddedBytes } = getTCPOptionsMetrics(layer.options);
  return TCP_HEADER_LENGTH + Math.min(paddedBytes, TCP_MAX_OPTIONS_LENGTH);
}

function pushUint16(out: number[], value: number): void {
  out.push((value >>> 8) & 0xff, value & 0xff);
}

function pushUint32(out: number[], value: number): void {
  out.push(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

/**
 * Encodes a TCP header with optional TCP options and 32-bit zero padding
 * (RFC 9293 Section 3.1 / RFC 8200 §8.1).
 * Keeps a computed checksum of 0x0000 as 0x0000 per RFC 9293.
 */
export function encodeTCP(layer: TCPLayer, ctx: EncodeTCPContext): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];
  const resolvedAutoValues: Record<string, number> = {};

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

  // Encode TCP options in order
  const optionBytes: number[] = [];
  const optionSpans: RelativeFieldSpan[] = [];
  const hasTimestamps = layer.options.some((opt) => opt.kind === 'timestamps');
  let seenEol = false;
  let warnedAfterEol = false;

  for (let i = 0; i < layer.options.length; i++) {
    const opt = layer.options[i];
    const optPrefix = `options[${i}]`;
    const optNum = i + 1;

    if (seenEol && !warnedAfterEol) {
      warnings.push({
        layerIndex: ctx.layerIndex,
        fieldId: 'options',
        message:
          'TCP options contain bytes after End of Option List (Kind 0); receivers stop parsing options at EOL (RFC 9293 §3.2).',
      });
      warnedAfterEol = true;
    }

    const pushSpan = (fieldId: string, label: string, byteLength: number) => {
      const bitOffset = (TCP_HEADER_LENGTH + optionBytes.length - byteLength) * 8;
      optionSpans.push({
        fieldId,
        label,
        bitOffset,
        bitLength: byteLength * 8,
      });
    };

    switch (opt.kind) {
      case 'eol': {
        seenEol = true;
        optionBytes.push(TCP_OPT_EOL);
        pushSpan(`${optPrefix}.eol.kind`, `Opt #${optNum}: EOL (0)`, 1);
        break;
      }

      case 'nop': {
        optionBytes.push(TCP_OPT_NOP);
        pushSpan(`${optPrefix}.nop.kind`, `Opt #${optNum}: NOP (1)`, 1);
        break;
      }

      case 'mss': {
        if (!layer.flags.syn) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.mss.mss`,
            message: 'TCP MSS option is only meaningful in SYN segments (RFC 9293 §3.7.1).',
          });
        }
        const mssErr = validateUintRange(opt.mss, 0xffff, 'MSS');
        if (mssErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.mss.mss`,
            message: mssErr,
          });
        }
        optionBytes.push(TCP_OPT_MSS);
        pushSpan(`${optPrefix}.mss.kind`, `Opt #${optNum}: MSS Kind (2)`, 1);
        optionBytes.push(4);
        pushSpan(`${optPrefix}.mss.length`, `Opt #${optNum}: MSS Len (4)`, 1);
        pushUint16(optionBytes, mssErr === null ? opt.mss : 0);
        pushSpan(`${optPrefix}.mss.mss`, `Opt #${optNum}: MSS`, 2);
        break;
      }

      case 'windowScale': {
        if (!layer.flags.syn) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.windowScale.shiftCount`,
            message: 'TCP Window Scale option is only meaningful in SYN segments (RFC 7323 §2.2).',
          });
        }
        const shiftErr = validateUintRange(opt.shiftCount, 0xff, 'Window Scale Shift Count');
        if (shiftErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.windowScale.shiftCount`,
            message: shiftErr,
          });
        } else if (opt.shiftCount > TCP_MAX_WINDOW_SCALE_SHIFT) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.windowScale.shiftCount`,
            message: `TCP Window Scale shift count (${opt.shiftCount}) exceeds the maximum of ${TCP_MAX_WINDOW_SCALE_SHIFT} (RFC 7323 §2.3).`,
          });
        }
        optionBytes.push(TCP_OPT_WINDOW_SCALE);
        pushSpan(`${optPrefix}.windowScale.kind`, `Opt #${optNum}: WScale Kind (3)`, 1);
        optionBytes.push(3);
        pushSpan(`${optPrefix}.windowScale.length`, `Opt #${optNum}: WScale Len (3)`, 1);
        optionBytes.push(shiftErr === null ? opt.shiftCount : 0);
        pushSpan(`${optPrefix}.windowScale.shiftCount`, `Opt #${optNum}: WScale Shift`, 1);
        break;
      }

      case 'sackPermitted': {
        if (!layer.flags.syn) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.sackPermitted.kind`,
            message: 'TCP SACK-Permitted option is only meaningful in SYN segments (RFC 2018 §2).',
          });
        }
        optionBytes.push(TCP_OPT_SACK_PERMITTED);
        pushSpan(`${optPrefix}.sackPermitted.kind`, `Opt #${optNum}: SACK-Perm Kind (4)`, 1);
        optionBytes.push(2);
        pushSpan(`${optPrefix}.sackPermitted.length`, `Opt #${optNum}: SACK-Perm Len (2)`, 1);
        break;
      }

      case 'sack': {
        const blockCount = opt.blocks.length;
        const sackLen = 2 + blockCount * 8;
        if (blockCount === 0) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.sack.length`,
            message: 'TCP SACK option requires at least 1 block (RFC 2018 §3).',
          });
        } else if (blockCount > 4) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.sack.length`,
            message: `TCP SACK option with ${blockCount} blocks (${sackLen} bytes) cannot fit in the 40-byte TCP options space (maximum 4 blocks, RFC 2018 §3).`,
          });
        } else if (blockCount > 3 && hasTimestamps) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.sack.length`,
            message: `TCP SACK option with ${blockCount} blocks cannot fit alongside TCP Timestamps (10 bytes) in the 40-byte options space (maximum 3 blocks with Timestamps, RFC 2018 §3).`,
          });
        }
        if (sackLen > 255) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.sack.length`,
            message: `TCP SACK option length (${sackLen} bytes) exceeds 255 bytes.`,
          });
        }

        optionBytes.push(TCP_OPT_SACK);
        pushSpan(`${optPrefix}.sack.kind`, `Opt #${optNum}: SACK Kind (5)`, 1);
        optionBytes.push(sackLen & 0xff);
        pushSpan(`${optPrefix}.sack.length`, `Opt #${optNum}: SACK Len (${sackLen})`, 1);

        for (let b = 0; b < blockCount; b++) {
          const block = opt.blocks[b];
          const leftFieldId = `${optPrefix}.sack.blocks[${b}].left`;
          const rightFieldId = `${optPrefix}.sack.blocks[${b}].right`;

          const leftErr = validateUintRange(block.left, 0xffffffff, `SACK Block #${b + 1} Left Edge`);
          if (leftErr !== null) {
            errors.push({ layerIndex: ctx.layerIndex, fieldId: leftFieldId, message: leftErr });
          }
          const rightErr = validateUintRange(
            block.right,
            0xffffffff,
            `SACK Block #${b + 1} Right Edge`,
          );
          if (rightErr !== null) {
            errors.push({ layerIndex: ctx.layerIndex, fieldId: rightFieldId, message: rightErr });
          }

          pushUint32(optionBytes, leftErr === null ? block.left : 0);
          pushSpan(leftFieldId, `Opt #${optNum}: SACK[${b + 1}] Left`, 4);
          pushUint32(optionBytes, rightErr === null ? block.right : 0);
          pushSpan(rightFieldId, `Opt #${optNum}: SACK[${b + 1}] Right`, 4);
        }
        break;
      }

      case 'timestamps': {
        const tsValErr = validateUintRange(opt.tsVal, 0xffffffff, 'TSval');
        if (tsValErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamps.tsVal`,
            message: tsValErr,
          });
        }
        const tsEcrErr = validateUintRange(opt.tsEcr, 0xffffffff, 'TSecr');
        if (tsEcrErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamps.tsEcr`,
            message: tsEcrErr,
          });
        }
        optionBytes.push(TCP_OPT_TIMESTAMPS);
        pushSpan(`${optPrefix}.timestamps.kind`, `Opt #${optNum}: TS Kind (8)`, 1);
        optionBytes.push(10);
        pushSpan(`${optPrefix}.timestamps.length`, `Opt #${optNum}: TS Len (10)`, 1);
        pushUint32(optionBytes, tsValErr === null ? opt.tsVal : 0);
        pushSpan(`${optPrefix}.timestamps.tsVal`, `Opt #${optNum}: TSval`, 4);
        pushUint32(optionBytes, tsEcrErr === null ? opt.tsEcr : 0);
        pushSpan(`${optPrefix}.timestamps.tsEcr`, `Opt #${optNum}: TSecr`, 4);
        break;
      }

      case 'raw': {
        const kindErr = validateUintRange(opt.optionKind, 0xff, 'Option Kind');
        if (kindErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.raw.kind`,
            message: kindErr,
          });
        }
        const dataParsed = parseHexBytes(opt.dataHex);
        if (!dataParsed.ok) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.raw.data`,
            message: dataParsed.error,
          });
        }
        const dataBytes = dataParsed.ok ? dataParsed.value : new Uint8Array(0);
        const autoLen = 2 + dataBytes.length;
        resolvedAutoValues[`${optPrefix}.raw.length`] = autoLen;

        optionBytes.push(kindErr === null ? opt.optionKind : 0);
        pushSpan(`${optPrefix}.raw.kind`, `Opt #${optNum}: Raw Kind (${opt.optionKind})`, 1);

        if (opt.length.mode === 'auto') {
          if (autoLen > 0xff) {
            errors.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: `Auto TCP option Length (${autoLen}) exceeds the 255-byte 8-bit limit (RFC 9293 §3.1).`,
            });
          }
          optionBytes.push(autoLen & 0xff);
          pushSpan(`${optPrefix}.raw.length`, `Opt #${optNum}: Raw Len (${autoLen})`, 1);
        } else if (opt.length.mode === 'manual') {
          const lenErr = validateUintRange(opt.length.value, 0xff, 'Option Length');
          if (lenErr !== null) {
            errors.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: lenErr,
            });
          } else if (opt.length.value < 2) {
            errors.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: `TCP option Length must be at least 2 (got ${opt.length.value}, RFC 9293 §3.1).`,
            });
          } else if (dataParsed.ok && opt.length.value !== autoLen) {
            warnings.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: `Manual TCP option Length (${opt.length.value}) differs from actual encoded length (${autoLen} bytes).`,
            });
          }
          optionBytes.push(lenErr === null ? opt.length.value : 0);
          pushSpan(
            `${optPrefix}.raw.length`,
            `Opt #${optNum}: Raw Len (${lenErr === null ? opt.length.value : '?'})`,
            1,
          );
        }
        // mode === 'none': omit Length byte and emit [optionKind, ...dataBytes] verbatim

        if (dataBytes.length > 0) {
          for (let d = 0; d < dataBytes.length; d++) {
            optionBytes.push(dataBytes[d]);
          }
          pushSpan(`${optPrefix}.raw.data`, `Opt #${optNum}: Raw Data`, dataBytes.length);
        }
        break;
      }
    }
  }

  const rawOptionsLen = optionBytes.length;
  const paddingLen = (4 - (rawOptionsLen % 4)) % 4;
  const paddedOptionsLen = rawOptionsLen + paddingLen;
  const autoDataOffset = TCP_DEFAULT_DATA_OFFSET + paddedOptionsLen / 4;

  if (rawOptionsLen > TCP_MAX_OPTIONS_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'options',
      message: `TCP options exceed the ${TCP_MAX_OPTIONS_LENGTH}-byte maximum (got ${rawOptionsLen} bytes; Data Offset cannot exceed ${TCP_MAX_DATA_OFFSET} per RFC 9293 §3.1).`,
    });
  }

  if (paddingLen > 0) {
    optionSpans.push({
      fieldId: 'optionsPadding',
      label: 'Options Padding',
      bitOffset: (TCP_HEADER_LENGTH + rawOptionsLen) * 8,
      bitLength: paddingLen * 8,
    });
  }

  const headerLength = TCP_HEADER_LENGTH + paddedOptionsLen;

  let dataOffsetValue = autoDataOffset;
  if (layer.dataOffset.mode === 'manual') {
    const doErr = validateUintRange(layer.dataOffset.value, TCP_MAX_DATA_OFFSET, 'Data Offset');
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
      } else if (dataOffsetValue !== autoDataOffset) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'dataOffset',
          message: `Using manual Data Offset ${dataOffsetValue} (computed value is ${autoDataOffset} for ${headerLength}-byte header).`,
        });
      }
    }
  }

  const segmentLength = headerLength + ctx.upperBytes.length;
  if (segmentLength > 0xffff) {
    errors.push({
      layerIndex: ctx.layerIndex,
      message: `TCP segment length exceeds the 65535-byte limit (got ${segmentLength} bytes).`,
    });
  }

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const header = new Uint8Array(headerLength);
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
  for (let i = 0; i < optionBytes.length; i++) {
    header[TCP_HEADER_LENGTH + i] = optionBytes[i];
  }
  // Trailing padding bytes (if any) are already 0 in Uint8Array

  let autoChecksum = 0;
  if (ctx.ip.status === 'valid') {
    const segment = concatBytes(header, ctx.upperBytes);
    const csumResult =
      ctx.ip.version === 4
        ? ipv4PseudoHeaderChecksum({
            srcIp: ctx.ip.srcIp,
            dstIp: ctx.ip.dstIp,
            protocol: IP_PROTOCOL_TCP,
            segment,
          })
        : ipv6PseudoHeaderChecksum({
            srcIp: ctx.ip.srcIp,
            dstIp: ctx.ip.dstIp,
            nextHeader: IP_PROTOCOL_TCP,
            segment,
          });
    if (!csumResult.ok) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'checksum', message: csumResult.error });
      return { ok: false, errors, warnings };
    }
    autoChecksum = csumResult.value;
  } else if (ctx.ip.status === 'absent' && layer.checksum.mode === 'auto') {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: 'No underlying IPv4 or IPv6 layer for pseudo-header; setting TCP Checksum to 0x0000.',
    });
  }

  const checksumValue = layer.checksum.mode === 'manual' ? layer.checksum.value : autoChecksum;
  writeUint16BE(header, 16, checksumValue);

  if (
    layer.checksum.mode === 'manual' &&
    ctx.ip.status === 'valid' &&
    checksumValue !== autoChecksum
  ) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'checksum',
      message: `Using manual TCP Checksum 0x${checksumValue.toString(16).padStart(4, '0')} (computed value is 0x${autoChecksum.toString(16).padStart(4, '0')}).`,
    });
  }

  resolvedAutoValues.dataOffset = autoDataOffset;
  resolvedAutoValues.checksum = autoChecksum;

  return {
    ok: true,
    bytes: header,
    spans: optionSpans.length > 0 ? [...TCP_FIELD_SPANS, ...optionSpans] : TCP_FIELD_SPANS,
    warnings,
    resolvedAutoValues,
  };
}

export const tcpDefinition: LayerDefinition<TCPLayer, 'tcp'> = {
  type: 'tcp',
  minHeaderLength: TCP_HEADER_LENGTH,
  createDefault: createDefaultTCP,
  headerLength: (layer) => getTCPHeaderLength(layer),
  encode: (layer, ctx) =>
    encodeTCP(layer, {
      layerIndex: ctx.layerIndex,
      upperBytes: ctx.upperBytes,
      ip: ctx.ip,
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
      return { tcp: { status: 'valid', srcPort: layer.srcPort, dstPort: layer.dstPort } };
    }
    return { tcp: { status: 'invalid' } };
  },
  decode: decodeTCPLayer,
  validatePermalink: validateTCPPermalink,
  fieldDocs: TCP_FIELD_DOCS,
  protocols: {
    ipProtocol: IP_PROTOCOL_TCP,
  },
};
