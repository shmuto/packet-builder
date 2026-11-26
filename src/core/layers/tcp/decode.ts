import { readUint16BE, readUint32BE } from '../../bytes';
import { computePseudoChecksum, formatSpacedHexBytes, isAllZero } from '../decodeHelpers';
import type { DecodeLayerContext, LayerDecodeResult } from '../definition';
import {
  autoValue,
  manualValue,
  type TCPLayer,
  type TCPOption,
  type TCPSackBlock,
} from '../types';
import {
  IP_PROTOCOL_TCP,
  TCP_DEFAULT_DATA_OFFSET,
  TCP_HEADER_LENGTH,
  TCP_OPT_EOL,
  TCP_OPT_MSS,
  TCP_OPT_NOP,
  TCP_OPT_SACK,
  TCP_OPT_SACK_PERMITTED,
  TCP_OPT_TIMESTAMPS,
  TCP_OPT_WINDOW_SCALE,
} from './index';

function decodeTCPOptions(optBytes: Uint8Array, notes: string[]): TCPOption[] {
  const options: TCPOption[] = [];

  const pushMalformedRaw = (slice: Uint8Array, note: string) => {
    notes.push(note);
    if (slice.length === 1) {
      options.push({
        kind: 'raw',
        optionKind: slice[0],
        length: { mode: 'none' },
        dataHex: '',
      });
      return;
    }
    const lenByte = slice[1];
    if (lenByte < 2) {
      options.push({
        kind: 'raw',
        optionKind: slice[0],
        length: { mode: 'none' },
        dataHex: formatSpacedHexBytes(slice.subarray(1)),
      });
      return;
    }
    options.push({
      kind: 'raw',
      optionKind: slice[0],
      length: lenByte === slice.length ? autoValue() : manualValue(lenByte),
      dataHex: formatSpacedHexBytes(slice.subarray(2)),
    });
  };

  let i = 0;
  while (i < optBytes.length) {
    const kind = optBytes[i];

    if (kind === TCP_OPT_EOL) {
      // Stop without adding a synthetic EOL if remaining bytes are just 32-bit zero padding
      if (i > 0 && Math.ceil(i / 4) * 4 === optBytes.length && isAllZero(optBytes.subarray(i))) {
        break;
      }
      options.push({ kind: 'eol' });
      i += 1;
      if (i < optBytes.length && !isAllZero(optBytes.subarray(i))) {
        const trailing = optBytes.subarray(i);
        notes.push(
          `Preserved ${trailing.length} non-zero byte(s) after TCP End of Option List (Kind 0) as a raw option block.`,
        );
        options.push({
          kind: 'raw',
          optionKind: trailing[0],
          length: { mode: 'none' },
          dataHex: formatSpacedHexBytes(trailing.subarray(1)),
        });
        break;
      }
      continue;
    }

    if (kind === TCP_OPT_NOP) {
      options.push({ kind: 'nop' });
      i += 1;
      continue;
    }

    // TLV-formatted option (Kind + Length + Data)
    if (i + 1 >= optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Truncated TCP option (Kind ${kind}) missing Length byte; remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    const optLen = optBytes[i + 1];
    if (optLen < 2) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed TCP option (Kind ${kind}) has Length ${optLen} (< 2); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (i + optLen > optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed TCP option (Kind ${kind}) has Length ${optLen} exceeding remaining ${optBytes.length - i} option byte(s); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (kind === TCP_OPT_MSS) {
      if (optLen !== 4) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP MSS option (Kind 2) has Length ${optLen} (expected 4); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({ kind: 'mss', mss: readUint16BE(optBytes, i + 2) });
    } else if (kind === TCP_OPT_WINDOW_SCALE) {
      if (optLen !== 3) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP Window Scale option (Kind 3) has Length ${optLen} (expected 3); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({ kind: 'windowScale', shiftCount: optBytes[i + 2] });
    } else if (kind === TCP_OPT_SACK_PERMITTED) {
      if (optLen !== 2) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP SACK-Permitted option (Kind 4) has Length ${optLen} (expected 2); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({ kind: 'sackPermitted' });
    } else if (kind === TCP_OPT_SACK) {
      if (optLen < 10 || (optLen - 2) % 8 !== 0) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP SACK option (Kind 5) has Length ${optLen} (expected 2 + 8n, n >= 1); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      const blockCount = (optLen - 2) / 8;
      const blocks: TCPSackBlock[] = [];
      for (let b = 0; b < blockCount; b++) {
        const bOff = i + 2 + b * 8;
        blocks.push({
          left: readUint32BE(optBytes, bOff),
          right: readUint32BE(optBytes, bOff + 4),
        });
      }
      options.push({ kind: 'sack', blocks });
    } else if (kind === TCP_OPT_TIMESTAMPS) {
      if (optLen !== 10) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed TCP Timestamps option (Kind 8) has Length ${optLen} (expected 10); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({
        kind: 'timestamps',
        tsVal: readUint32BE(optBytes, i + 2),
        tsEcr: readUint32BE(optBytes, i + 6),
      });
    } else {
      options.push({
        kind: 'raw',
        optionKind: kind,
        length: autoValue(),
        dataHex: formatSpacedHexBytes(optBytes.subarray(i + 2, i + optLen)),
      });
    }

    i += optLen;
  }

  return options;
}

export function decodeTCPLayer(
  bytes: Uint8Array,
  offset: number,
  ctx: DecodeLayerContext,
): LayerDecodeResult {
  const srcPort = readUint16BE(bytes, offset);
  const dstPort = readUint16BE(bytes, offset + 2);
  const seqNumber = readUint32BE(bytes, offset + 4);
  const ackNumber = readUint32BE(bytes, offset + 8);
  const dataOffsetAndReserved = bytes[offset + 12];
  const dataOffset = dataOffsetAndReserved >>> 4;
  const reserved = dataOffsetAndReserved & 0x0f;
  const flagsByte = bytes[offset + 13];
  const windowSize = readUint16BE(bytes, offset + 14);
  const checksum = readUint16BE(bytes, offset + 16);
  const urgentPointer = readUint16BE(bytes, offset + 18);

  const segmentLength = bytes.length - offset;
  const declaredHeaderLength = dataOffset * 4;
  let options: TCPOption[] = [];
  let payloadOffset = offset + TCP_HEADER_LENGTH;
  let dataOffsetField =
    dataOffset === TCP_DEFAULT_DATA_OFFSET ? autoValue<number>() : manualValue(dataOffset);

  if (dataOffset > TCP_DEFAULT_DATA_OFFSET) {
    if (segmentLength >= declaredHeaderLength) {
      const optBytes = bytes.subarray(offset + TCP_HEADER_LENGTH, offset + declaredHeaderLength);
      options = decodeTCPOptions(optBytes, ctx.notes);
      payloadOffset = offset + declaredHeaderLength;
      dataOffsetField = autoValue();
    } else {
      ctx.notes.push(
        `TCP Data Offset is ${dataOffset} (${declaredHeaderLength} bytes), exceeding the ${segmentLength}-byte segment; bytes beyond the 20-byte base header are placed in Payload.`,
      );
    }
  }
  if (reserved !== 0) {
    ctx.notes.push(
      `TCP Reserved bits were non-zero (0x${reserved.toString(16)}); the encoder resets Reserved to 0 per RFC 9293, so re-encoded bytes and checksum will differ from the original input.`,
    );
  }

  const segmentCopy = new Uint8Array(bytes.subarray(offset));
  segmentCopy[16] = 0;
  segmentCopy[17] = 0;
  const expectedChecksum = ctx.ip
    ? (() => {
        const csumRes = computePseudoChecksum(ctx.ip, IP_PROTOCOL_TCP, segmentCopy);
        return csumRes.ok ? csumRes.value : null;
      })()
    : null;

  const tcpLayer: TCPLayer = {
    type: 'tcp',
    srcPort,
    dstPort,
    seqNumber,
    ackNumber,
    dataOffset: dataOffsetField,
    flags: {
      cwr: (flagsByte & 0x80) !== 0,
      ece: (flagsByte & 0x40) !== 0,
      urg: (flagsByte & 0x20) !== 0,
      ack: (flagsByte & 0x10) !== 0,
      psh: (flagsByte & 0x08) !== 0,
      rst: (flagsByte & 0x04) !== 0,
      syn: (flagsByte & 0x02) !== 0,
      fin: (flagsByte & 0x01) !== 0,
    },
    windowSize,
    checksum:
      expectedChecksum !== null && checksum === expectedChecksum
        ? autoValue()
        : manualValue(checksum),
    urgentPointer,
    options,
  };

  const upper = ctx.decodeByTcpPort(bytes, payloadOffset, srcPort, dstPort, {
    dataOffsetAuto: dataOffsetField.mode === 'auto',
    dataOffsetValue: dataOffsetField.mode === 'manual' ? dataOffsetField.value : dataOffset,
  });

  return {
    layers: [tcpLayer, ...upper.layers],
    payload: upper.payload,
  };
}
