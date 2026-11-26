import {
  formatIPv6,
  parseIPv6,
  readUint16BE,
  readUint32BE,
  writeUint16BE,
  writeUint32BE,
} from '../../bytes';
import { err, ok, type Result } from '../../result';
import { isAllZero } from '../decodeHelpers';
import {
  MAX_IP_LAYERS,
  type DecodeLayerContext,
  type FieldDoc,
  type LayerDefinition,
  type ProtocolTables,
  type PseudoIPInfo,
} from '../definition';
import {
  expectNumber,
  expectString,
  validateAutoOrManualNumber,
  validateExactKeys,
} from '../permalinkHelpers';
import { getDefaultProtocolTables } from '../registry';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type IPv6Layer,
  type LayerEncodeResult,
  type PacketError,
  type PacketWarning,
  type RelativeFieldSpan,
} from '../types';

/** Fixed IPv6 header length without extension headers (40 bytes, RFC 8200 §3) */
export const IPV6_HEADER_LENGTH = 40;
export const IPV6_VERSION = 6;
export const IPV6_MAX_FLOW_LABEL = 0xfffff;
export const IPV6_MAX_PAYLOAD_LENGTH = 0xffff;
/** EtherType for IPv6 (RFC 2464) */
export const ETHERTYPE_IPV6 = 0x86dd;
/** IANA IP Protocol / Next Header number for IPv6 encapsulation (6in4 / 6in6, RFC 4213 / RFC 2473) */
export const IP_PROTOCOL_IPV6 = 41;

const IPV6_EXTENSION_HEADER_NAMES: Readonly<Record<number, string>> = {
  0: 'Hop-by-Hop Options',
  43: 'Routing',
  44: 'Fragment',
  50: 'ESP',
  51: 'AH',
  60: 'Destination Options',
};

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

export const IPV6_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  version: {
    summary:
      '4-bit IP version number identifying the header format. Always 6 for IPv6 packets.',
    reference: 'RFC 8200 §3',
  },
  trafficClass: {
    summary:
      '8-bit quality-of-service field split into a 6-bit DSCP priority code and 2-bit ECN congestion indicator. Defaults to 0x00 for best-effort traffic.',
    reference: 'RFC 8200 §3 / RFC 2474 §3 / RFC 3168 §5',
  },
  flowLabel: {
    summary:
      '20-bit label identifying packets belonging to the same flow so routers can apply consistent forwarding or load-balancing. Set to 0 when unused.',
    reference: 'RFC 8200 §3 / RFC 6437 §2',
  },
  payloadLength: {
    summary:
      '16-bit length in bytes of the payload following the 40-byte fixed IPv6 header (including any extension headers). Maximum standard value is 65,535 bytes.',
    reference: 'RFC 8200 §3',
  },
  nextHeader: {
    summary:
      '8-bit IANA protocol number identifying the header immediately following the IPv6 header. Common values are 6 (TCP), 17 (UDP), 4 (IPv4), 41 (IPv6), 47 (GRE), and 58 (ICMPv6).',
    reference: 'RFC 8200 §3',
  },
  hopLimit: {
    summary:
      'Remaining router hops allowed before the packet is discarded; decremented by 1 at each forwarding node. Common initial value is 64.',
    reference: 'RFC 8200 §3',
  },
  srcIp: {
    summary:
      '128-bit IPv6 address of the packet originator, written in RFC 5952 canonical colon-hexadecimal notation.',
    reference: 'RFC 8200 §3',
  },
  dstIp: {
    summary:
      '128-bit IPv6 address of the intended recipient (or next-hop routing header target).',
    reference: 'RFC 8200 §3',
  },
};

export interface EncodeIPv6Context {
  readonly layerIndex: number;
  readonly upperLayerType: string | null;
  readonly upperBytesLength: number;
  readonly tables?: ProtocolTables;
}

/** Creates a default IPv6 header using the RFC 3849 documentation prefix (2001:db8::/32). */
export function createDefaultIPv6(): IPv6Layer {
  return {
    type: 'ipv6',
    trafficClass: 0,
    flowLabel: 0,
    payloadLength: autoValue(),
    nextHeader: autoValue(),
    hopLimit: 64,
    srcIp: '2001:db8::1',
    dstIp: '2001:db8::2',
  };
}

/**
 * Encodes a 40-byte fixed IPv6 header (RFC 8200 §3, no extension headers).
 */
export function encodeIPv6(layer: IPv6Layer, ctx: EncodeIPv6Context): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];
  const tables = ctx.tables ?? getDefaultProtocolTables();

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

  const mismatchWarning = tables.getIPv6MismatchWarning(ctx.upperLayerType);
  if (mismatchWarning !== null) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'nextHeader',
      message: mismatchWarning,
    });
  }

  const inferredNextHeader = tables.resolveIPv6NextHeader(ctx.upperLayerType);
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
  } else if (inferredNextHeader === null && mismatchWarning === null) {
    warnings.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'nextHeader',
      message:
        'No TCP / UDP / ICMPv6 / GRE / IPv4 / IPv6 upper layer found; defaulting Next Header to 0.',
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

function decodeIPv6Chain(
  bytes: Uint8Array,
  offset: number,
  ctx: DecodeLayerContext,
  depth: number,
) {
  const firstWord = readUint32BE(bytes, offset);
  const trafficClass = (firstWord >>> 20) & 0xff;
  const flowLabel = firstWord & 0xfffff;
  const payloadLength = readUint16BE(bytes, offset + 4);
  const nextHeader = bytes[offset + 6];
  const hopLimit = bytes[offset + 7];
  const srcIpBytes = bytes.subarray(offset + 8, offset + 24);
  const dstIpBytes = bytes.subarray(offset + 24, offset + 40);
  const ipInfo: PseudoIPInfo = { version: 6, srcIp: srcIpBytes, dstIp: dstIpBytes };

  const upperOffset = offset + IPV6_HEADER_LENGTH;
  const actualPayloadLength = bytes.length - upperOffset;
  let scopedBytes = bytes;
  let effectivePayloadLength = actualPayloadLength;
  const isJumbogramShape =
    payloadLength === 0 && nextHeader === 0 && actualPayloadLength > 0;

  if (depth === 0 && isJumbogramShape) {
    ctx.notes.push(
      'IPv6 Payload Length is 0 with Next Header 0 (Hop-by-Hop Options); Jumbogram (RFC 2675 §2) is not supported, so remaining bytes are kept as Payload.',
    );
  } else if (depth === 0 && payloadLength < actualPayloadLength) {
    const trailing = bytes.subarray(upperOffset + payloadLength);
    // Per RFC 8200 §3 / §8.1, upper-layer segments and checksums are bounded by IPv6 Payload Length.
    scopedBytes = bytes.subarray(0, upperOffset + payloadLength);
    effectivePayloadLength = payloadLength;
    const isInsideEthernet = offset > 0;
    if (isInsideEthernet) {
      if (isAllZero(trailing)) {
        ctx.notes.push(
          `Stripped ${trailing.length} trailing zero byte(s) of Ethernet padding beyond IPv6 Payload Length (${payloadLength}).`,
        );
      } else {
        ctx.notes.push(
          `Stripped ${trailing.length} trailing non-zero byte(s) of Ethernet padding/trailer beyond IPv6 Payload Length (${payloadLength}) per RFC 8200 §3; re-encoded bytes will omit these trailing bytes.`,
        );
      }
    } else {
      ctx.notes.push(
        `Stripped ${trailing.length} trailing byte(s) beyond IPv6 Payload Length (${payloadLength}) per RFC 8200 §3; re-encoded bytes will omit these trailing bytes.`,
      );
    }
  }

  let decodedUpperLayers: readonly { readonly type: string }[] = [];
  let payload: Uint8Array = scopedBytes.slice(upperOffset);

  if (depth === 0 && isJumbogramShape) {
    // Already noted as an unsupported RFC 2675 §2 Jumbogram; keep remaining bytes in Payload.
  } else if (Object.prototype.hasOwnProperty.call(IPV6_EXTENSION_HEADER_NAMES, nextHeader)) {
    ctx.notes.push(
      `IPv6 extension header Next Header ${nextHeader} (${IPV6_EXTENSION_HEADER_NAMES[nextHeader]}) is not decoded into a layer; remaining bytes kept as Payload.`,
    );
  } else {
    const upper = ctx.decodeByIPv6NextHeader(
      scopedBytes,
      upperOffset,
      nextHeader,
      ipInfo,
      depth,
    );
    decodedUpperLayers = upper.layers;
    payload = upper.payload;
  }

  const ipv6Layer: IPv6Layer = {
    type: 'ipv6',
    trafficClass,
    flowLabel,
    payloadLength:
      payloadLength === effectivePayloadLength ? autoValue() : manualValue(payloadLength),
    nextHeader: decodedUpperLayers.length > 0 ? autoValue() : manualValue(nextHeader),
    hopLimit,
    srcIp: formatIPv6(srcIpBytes),
    dstIp: formatIPv6(dstIpBytes),
  };

  return {
    layers: [ipv6Layer, ...decodedUpperLayers],
    payload,
  };
}

function validateIPv6Permalink(raw: Record<string, unknown>, ctx: string): Result<IPv6Layer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'trafficClass',
      'flowLabel',
      'payloadLength',
      'nextHeader',
      'hopLimit',
      'srcIp',
      'dstIp',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const trafficClass = expectNumber(obj, 'trafficClass', ctx);
  if (!trafficClass.ok) return trafficClass;
  const flowLabel = expectNumber(obj, 'flowLabel', ctx);
  if (!flowLabel.ok) return flowLabel;
  const payloadLength = validateAutoOrManualNumber(obj.payloadLength, `${ctx}.payloadLength`);
  if (!payloadLength.ok) return payloadLength;
  const nextHeader = validateAutoOrManualNumber(obj.nextHeader, `${ctx}.nextHeader`);
  if (!nextHeader.ok) return nextHeader;
  const hopLimit = expectNumber(obj, 'hopLimit', ctx);
  if (!hopLimit.ok) return hopLimit;
  const srcIp = expectString(obj, 'srcIp', ctx);
  if (!srcIp.ok) return srcIp;
  const dstIp = expectString(obj, 'dstIp', ctx);
  if (!dstIp.ok) return dstIp;
  return ok({
    type: 'ipv6',
    trafficClass: trafficClass.value,
    flowLabel: flowLabel.value,
    payloadLength: payloadLength.value,
    nextHeader: nextHeader.value,
    hopLimit: hopLimit.value,
    srcIp: srcIp.value,
    dstIp: dstIp.value,
  });
}

export const ipv6Definition: LayerDefinition<IPv6Layer, 'ipv6'> = {
  type: 'ipv6',
  minHeaderLength: IPV6_HEADER_LENGTH,
  createDefault: createDefaultIPv6,
  headerLength: () => IPV6_HEADER_LENGTH,
  encode: (layer, ctx) =>
    encodeIPv6(layer, {
      layerIndex: ctx.layerIndex,
      upperLayerType: ctx.upperLayerType,
      upperBytesLength: ctx.upperBytesLength,
      tables: ctx.tables,
    }),
  provideLowerContext(layer) {
    const src = parseIPv6(layer.srcIp);
    const dst = parseIPv6(layer.dstIp);
    if (src.ok && dst.ok) {
      return { ip: { status: 'valid', version: 6, srcIp: src.value, dstIp: dst.value } };
    }
    return { ip: { status: 'invalid', version: 6 } };
  },
  decodeStart(bytes, ctx) {
    if (bytes.length < IPV6_HEADER_LENGTH) {
      return err(
        `Packet is too short for an IPv6 header (need at least ${IPV6_HEADER_LENGTH} bytes, got ${bytes.length}).`,
      );
    }
    const version = bytes[0] >>> 4;
    if (version !== IPV6_VERSION) {
      return err(`Expected IPv6 (Version=6), but got Version=${version}.`);
    }
    return ok(decodeIPv6Chain(bytes, 0, ctx, 0));
  },
  decode(bytes, offset, ctx) {
    const remaining = bytes.length - offset;
    const isInner =
      ctx.carrier === 'ipv4Protocol' ||
      ctx.carrier === 'ipv6NextHeader' ||
      ctx.tunnelDepth > 0;

    if (!isInner) {
      if (remaining < IPV6_HEADER_LENGTH) {
        ctx.notes.push(
          `IPv6 header after ${ctx.enclosingLabel} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
        );
        return null;
      }
      const version = bytes[offset] >>> 4;
      if (version !== IPV6_VERSION) {
        ctx.notes.push(
          `IPv6 header has Version=${version} (expected Version=6); remaining bytes kept as Payload.`,
        );
        return null;
      }
      return decodeIPv6Chain(bytes, offset, ctx, 0);
    }

    if (remaining < IPV6_HEADER_LENGTH) {
      ctx.notes.push(
        `IPv6 header after ${ctx.enclosingLabel} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
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
    const innerPayloadLength = readUint16BE(bytes, offset + 4);
    if (innerVersion !== IPV6_VERSION) {
      ctx.notes.push(
        `Inner IPv6 header (${label}) has Version=${innerVersion} (expected Version=6); remaining bytes kept as Payload.`,
      );
      return null;
    }

    const innerAvailablePayload = remaining - IPV6_HEADER_LENGTH;
    if (innerPayloadLength < innerAvailablePayload) {
      ctx.notes.push(
        `Inner IPv6 Payload Length (${innerPayloadLength}) is smaller than the enclosing IP payload (${innerAvailablePayload} bytes after 40-byte header); inner packet and trailing bytes kept in Payload to preserve exact round-trip bytes.`,
      );
      return null;
    }

    return decodeIPv6Chain(bytes, offset, ctx, parentDepth + 1);
  },
  validatePermalink: validateIPv6Permalink,
  fieldDocs: IPV6_FIELD_DOCS,
  protocols: {
    etherType: ETHERTYPE_IPV6,
    etherTypeLabel: 'IPv6',
    ipProtocol: IP_PROTOCOL_IPV6,
  },
};
