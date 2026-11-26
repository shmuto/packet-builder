import { formatIPv4, readUint16BE } from '../../bytes';
import { internetChecksum } from '../../checksum';
import { err, ok, type Result } from '../../result';
import { formatSpacedHexBytes, isAllZero } from '../decodeHelpers';
import {
  MAX_IP_LAYERS,
  type BaseLayer,
  type DecodeLayerContext,
  type LayerDecodeResult,
  type PseudoIPInfo,
} from '../definition';
import { autoValue, manualValue, type IPv4Layer, type IPv4Option } from '../types';
import {
  IPV4_HEADER_LENGTH,
  IPV4_IHL,
  IPV4_OPT_EOL,
  IPV4_OPT_LSRR,
  IPV4_OPT_NOP,
  IPV4_OPT_ROUTER_ALERT,
  IPV4_OPT_RR,
  IPV4_OPT_SSRR,
  IPV4_OPT_TIMESTAMP,
  IPV4_VERSION,
} from './index';

function decodeIPv4Options(optBytes: Uint8Array, notes: string[]): IPv4Option[] {
  const options: IPv4Option[] = [];

  const pushMalformedRaw = (slice: Uint8Array, note: string) => {
    notes.push(note);
    if (slice.length === 1) {
      options.push({
        kind: 'raw',
        optionType: slice[0],
        length: { mode: 'none' },
        dataHex: '',
      });
      return;
    }
    const lenByte = slice[1];
    if (lenByte < 2) {
      options.push({
        kind: 'raw',
        optionType: slice[0],
        length: { mode: 'none' },
        dataHex: formatSpacedHexBytes(slice.subarray(1)),
      });
      return;
    }
    options.push({
      kind: 'raw',
      optionType: slice[0],
      length: lenByte === slice.length ? autoValue() : manualValue(lenByte),
      dataHex: formatSpacedHexBytes(slice.subarray(2)),
    });
  };

  let i = 0;
  while (i < optBytes.length) {
    const typeByte = optBytes[i];

    if (typeByte === IPV4_OPT_EOL) {
      if (i > 0 && Math.ceil(i / 4) * 4 === optBytes.length && isAllZero(optBytes.subarray(i))) {
        break;
      }
      options.push({ kind: 'eol' });
      i += 1;
      if (i < optBytes.length && !isAllZero(optBytes.subarray(i))) {
        const trailing = optBytes.subarray(i);
        notes.push(
          `Preserved ${trailing.length} non-zero byte(s) after IPv4 End of Option List (Type 0) as a raw option block.`,
        );
        options.push({
          kind: 'raw',
          optionType: trailing[0],
          length: { mode: 'none' },
          dataHex: formatSpacedHexBytes(trailing.subarray(1)),
        });
        break;
      }
      continue;
    }

    if (typeByte === IPV4_OPT_NOP) {
      options.push({ kind: 'nop' });
      i += 1;
      continue;
    }

    if (i + 1 >= optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Truncated IPv4 option (Type ${typeByte}) missing Length byte; remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    const optLen = optBytes[i + 1];
    if (optLen < 2) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed IPv4 option (Type ${typeByte}) has Length ${optLen} (< 2); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (i + optLen > optBytes.length) {
      pushMalformedRaw(
        optBytes.subarray(i),
        `Malformed IPv4 option (Type ${typeByte}) has Length ${optLen} exceeding remaining ${optBytes.length - i} option byte(s); remaining option bytes preserved as a raw block.`,
      );
      break;
    }

    if (
      typeByte === IPV4_OPT_RR ||
      typeByte === IPV4_OPT_LSRR ||
      typeByte === IPV4_OPT_SSRR
    ) {
      const kind =
        typeByte === IPV4_OPT_RR ? 'rr' : typeByte === IPV4_OPT_LSRR ? 'lsrr' : 'ssrr';
      if (optLen < 3 || (optLen - 3) % 4 !== 0) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed IPv4 ${kind.toUpperCase()} option (Type ${typeByte}) has Length ${optLen} (expected 3 + 4n); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      const ptr = optBytes[i + 2];
      const addrCount = (optLen - 3) / 4;
      const addresses: string[] = [];
      for (let a = 0; a < addrCount; a++) {
        const aOff = i + 3 + a * 4;
        addresses.push(formatIPv4(optBytes.subarray(aOff, aOff + 4)));
      }
      options.push({
        kind,
        pointer: ptr === 4 ? autoValue() : manualValue(ptr),
        addresses,
      });
    } else if (typeByte === IPV4_OPT_TIMESTAMP) {
      if (optLen < 4) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed IPv4 Timestamp option (Type 68) has Length ${optLen} (expected >= 4); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      const pointer = optBytes[i + 2];
      const ovflFlag = optBytes[i + 3];
      options.push({
        kind: 'timestamp',
        pointer,
        overflow: (ovflFlag >>> 4) & 0x0f,
        flag: ovflFlag & 0x0f,
        dataHex: formatSpacedHexBytes(optBytes.subarray(i + 4, i + optLen)),
      });
    } else if (typeByte === IPV4_OPT_ROUTER_ALERT) {
      if (optLen !== 4) {
        pushMalformedRaw(
          optBytes.subarray(i),
          `Malformed IPv4 Router Alert option (Type 148) has Length ${optLen} (expected 4); remaining option bytes preserved as a raw block.`,
        );
        break;
      }
      options.push({
        kind: 'routerAlert',
        value: readUint16BE(optBytes, i + 2),
      });
    } else {
      options.push({
        kind: 'raw',
        optionType: typeByte,
        length: autoValue(),
        dataHex: formatSpacedHexBytes(optBytes.subarray(i + 2, i + optLen)),
      });
    }

    i += optLen;
  }

  return options;
}

function decodeIPv4Chain(
  bytes: Uint8Array,
  offset: number,
  ctx: DecodeLayerContext,
  depth: number,
): { readonly layers: readonly BaseLayer[]; readonly payload: Uint8Array } {
  const ihl = bytes[offset] & 0x0f;
  const headerLength = ihl * 4;
  const tos = bytes[offset + 1];
  const totalLength = readUint16BE(bytes, offset + 2);
  const identification = readUint16BE(bytes, offset + 4);
  const flagsAndFrag = readUint16BE(bytes, offset + 6);
  const fragmentOffset = flagsAndFrag & 0x1fff;
  const ttl = bytes[offset + 8];
  const protocol = bytes[offset + 9];
  const headerChecksum = readUint16BE(bytes, offset + 10);
  const srcIpBytes = bytes.subarray(offset + 12, offset + 16);
  const dstIpBytes = bytes.subarray(offset + 16, offset + 20);
  const ipInfo: PseudoIPInfo = { version: 4, srcIp: srcIpBytes, dstIp: dstIpBytes };

  const actualTotalLength = bytes.length - offset;
  let scopedBytes = bytes;
  let effectiveTotalLength = actualTotalLength;

  if (depth === 0 && totalLength >= headerLength && totalLength < actualTotalLength) {
    const trailing = bytes.subarray(offset + totalLength);
    // Per RFC 791 / RFC 768 / RFC 9293 §3.1, upper-layer segments and checksums are bounded
    // strictly by the outermost IPv4 Total Length regardless of whether Ethernet padding bytes are zero or non-zero.
    scopedBytes = bytes.subarray(0, offset + totalLength);
    effectiveTotalLength = totalLength;
    if (isAllZero(trailing)) {
      ctx.notes.push(
        `Stripped ${trailing.length} trailing zero byte(s) of Ethernet padding beyond IPv4 Total Length (${totalLength}).`,
      );
    } else {
      ctx.notes.push(
        `Stripped ${trailing.length} trailing non-zero byte(s) of Ethernet padding/trailer beyond IPv4 Total Length (${totalLength}) per RFC 791/768/9293; re-encoded bytes will omit these trailing bytes.`,
      );
    }
  }

  const headerCopy = new Uint8Array(scopedBytes.subarray(offset, offset + headerLength));
  headerCopy[10] = 0;
  headerCopy[11] = 0;
  const computedHeaderChecksum = internetChecksum(headerCopy);

  const options =
    ihl > IPV4_IHL
      ? decodeIPv4Options(
          scopedBytes.subarray(offset + IPV4_HEADER_LENGTH, offset + headerLength),
          ctx.notes,
        )
      : [];

  const upperOffset = offset + headerLength;
  let decodedUpperLayers: readonly BaseLayer[] = [];
  let payload: Uint8Array = scopedBytes.slice(upperOffset);

  if (fragmentOffset !== 0) {
    // RFC 791: non-initial fragments carry continuation payload rather than an L4 header
    ctx.notes.push(
      `Non-initial IPv4 fragment (Fragment Offset = ${fragmentOffset}); upper-layer header is not decoded per RFC 791 and remaining bytes are kept as Payload.`,
    );
  } else {
    const upper = ctx.decodeByIPv4Protocol(
      scopedBytes,
      upperOffset,
      protocol,
      ipInfo,
      depth,
    );
    decodedUpperLayers = upper.layers;
    payload = upper.payload;
  }

  const ipv4Layer: IPv4Layer = {
    type: 'ipv4',
    ihl: autoValue(),
    tos,
    totalLength: totalLength === effectiveTotalLength ? autoValue() : manualValue(totalLength),
    identification,
    flags: {
      reserved: (flagsAndFrag & 0x8000) !== 0,
      df: (flagsAndFrag & 0x4000) !== 0,
      mf: (flagsAndFrag & 0x2000) !== 0,
    },
    fragmentOffset,
    ttl,
    protocol: decodedUpperLayers.length > 0 ? autoValue() : manualValue(protocol),
    headerChecksum:
      headerChecksum === computedHeaderChecksum ? autoValue() : manualValue(headerChecksum),
    srcIp: formatIPv4(srcIpBytes),
    dstIp: formatIPv4(dstIpBytes),
    options,
  };

  return {
    layers: [ipv4Layer, ...decodedUpperLayers],
    payload,
  };
}

export function decodeIPv4Start(
  bytes: Uint8Array,
  ctx: DecodeLayerContext,
): Result<{ readonly layers: readonly BaseLayer[]; readonly payload: Uint8Array }> {
  if (bytes.length < IPV4_HEADER_LENGTH) {
    return err(
      `Packet is too short for an IPv4 header (need at least ${IPV4_HEADER_LENGTH} bytes, got ${bytes.length}).`,
    );
  }
  const version = bytes[0] >>> 4;
  const ihl = bytes[0] & 0x0f;
  if (version !== IPV4_VERSION) {
    return err(`Expected IPv4 (Version=4), but got Version=${version}.`);
  }
  if (ihl < IPV4_IHL) {
    return err(
      `IPv4 header has invalid IHL=${ihl} (minimum is 5 / 20 bytes per RFC 791 §3.1).`,
    );
  }
  const headerLength = ihl * 4;
  if (bytes.length < headerLength) {
    return err(
      `Packet is too short for IPv4 header with IHL=${ihl} (need at least ${headerLength} bytes, got ${bytes.length}).`,
    );
  }
  return ok(decodeIPv4Chain(bytes, 0, ctx, 0));
}

export function decodeIPv4Layer(
  bytes: Uint8Array,
  offset: number,
  ctx: DecodeLayerContext,
): LayerDecodeResult {
  const remaining = bytes.length - offset;
  const isInner =
    ctx.carrier === 'ipv4Protocol' ||
    ctx.carrier === 'ipv6NextHeader' ||
    ctx.tunnelDepth > 0;

  if (!isInner) {
    if (remaining < IPV4_HEADER_LENGTH) {
      ctx.notes.push(
        `IPv4 header after ${ctx.enclosingLabel} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
      );
      return null;
    }
    const version = bytes[offset] >>> 4;
    const ihl = bytes[offset] & 0x0f;
    if (version !== IPV4_VERSION || ihl < IPV4_IHL) {
      ctx.notes.push(
        `IPv4 header has Version=${version}, IHL=${ihl} (expected Version=4, IHL >= 5); remaining bytes kept as Payload.`,
      );
      return null;
    }
    const headerLength = ihl * 4;
    if (remaining < headerLength) {
      ctx.notes.push(
        `IPv4 header after ${ctx.enclosingLabel} is truncated (${remaining} bytes available, IHL=${ihl} requires ${headerLength} bytes); remaining bytes kept as Payload.`,
      );
      return null;
    }
    return decodeIPv4Chain(bytes, offset, ctx, 0);
  }

  if (remaining < IPV4_HEADER_LENGTH) {
    ctx.notes.push(
      `IPv4 header after ${ctx.enclosingLabel} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
    );
    return null;
  }

  const parentDepth =
    ctx.carrier === 'ipv4Protocol' || ctx.carrier === 'ipv6NextHeader'
      ? ctx.tunnelDepth
      : ctx.tunnelDepth - 1;
  const label =
    ctx.carrier === 'ipv4Protocol' || ctx.carrier === 'ipv6NextHeader'
      ? ctx.enclosingLabel
      : `after ${ctx.enclosingLabel}`;

  if (parentDepth + 1 >= MAX_IP_LAYERS) {
    ctx.notes.push(
      `IP tunnel layer limit (${MAX_IP_LAYERS} IP layers) exceeded; remaining bytes kept as Payload.`,
    );
    return null;
  }

  const innerVersion = bytes[offset] >>> 4;
  const innerIhl = bytes[offset] & 0x0f;
  const innerTotalLength = readUint16BE(bytes, offset + 2);
  if (innerVersion !== IPV4_VERSION || innerIhl < IPV4_IHL) {
    ctx.notes.push(
      `Inner IPv4 header (${label}) has Version=${innerVersion}, IHL=${innerIhl} (expected Version=4, IHL >= 5); remaining bytes kept as Payload.`,
    );
    return null;
  }
  const innerHeaderLength = innerIhl * 4;
  if (remaining < innerHeaderLength) {
    ctx.notes.push(
      `Inner IPv4 header (${label}) is truncated (${remaining} bytes available, IHL=${innerIhl} requires ${innerHeaderLength} bytes); remaining bytes kept as Payload.`,
    );
    return null;
  }
  if (innerTotalLength >= innerHeaderLength && innerTotalLength < remaining) {
    ctx.notes.push(
      `Inner IPv4 Total Length (${innerTotalLength}) is smaller than the enclosing IP payload (${remaining} bytes); inner packet and trailing bytes kept in Payload to preserve exact round-trip bytes.`,
    );
    return null;
  }

  return decodeIPv4Chain(bytes, offset, ctx, parentDepth + 1);
}
