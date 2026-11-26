import { parseHexBytes, parseIPv4, writeUint16BE } from '../bytes';
import { internetChecksum } from '../checksum';
import type {
  IPv4Layer,
  IPv4Option,
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';
import { validateUintRange } from './types';

/** Base IPv4 header length without options (IHL=5, 20 bytes, RFC 791 §3.1) */
export const IPV4_HEADER_LENGTH = 20;
export const IPV4_VERSION = 4;
export const IPV4_IHL = 5;
export const IPV4_MAX_IHL = 15;
export const IPV4_MAX_OPTIONS_LENGTH = (IPV4_MAX_IHL - IPV4_IHL) * 4; // 40 bytes
export const IPV4_MAX_TOTAL_LENGTH = 0xffff;

/** IP protocol numbers (IANA / RFC 792, 2003, 9293, 768, 4213, 2784) */
export const IP_PROTOCOL_ICMP = 1;
export const IP_PROTOCOL_IGMP = 2;
export const IP_PROTOCOL_IPIP = 4;
export const IP_PROTOCOL_TCP = 6;
export const IP_PROTOCOL_UDP = 17;
export const IP_PROTOCOL_IPV6 = 41;
export const IP_PROTOCOL_GRE = 47;

/** IPv4 Option Type bytes (RFC 791 §3.1, RFC 2113 §2.1) */
export const IPV4_OPT_EOL = 0;
export const IPV4_OPT_NOP = 1;
export const IPV4_OPT_RR = 7;
export const IPV4_OPT_TIMESTAMP = 68;
export const IPV4_OPT_LSRR = 131;
export const IPV4_OPT_SSRR = 137;
export const IPV4_OPT_ROUTER_ALERT = 148;

export interface IPv4OptionTypeBreakdown {
  /** 1-bit Copied flag (bit 0): 0 = not copied on fragmentation, 1 = copied into all fragments */
  readonly copied: 0 | 1;
  /** 2-bit Option Class (bits 1-2): 0 = control, 2 = debugging and measurement */
  readonly optionClass: number;
  /** 5-bit Option Number (bits 3-7) */
  readonly number: number;
}

/**
 * Splits an 8-bit IPv4 option type byte into copied (1b), class (2b), and number (5b) per RFC 791 §3.1.
 */
export function decodeIPv4OptionTypeByte(typeByte: number): IPv4OptionTypeBreakdown {
  const byte = typeByte & 0xff;
  return {
    copied: ((byte >>> 7) & 0x01) as 0 | 1,
    optionClass: (byte >>> 5) & 0x03,
    number: byte & 0x1f,
  };
}

/**
 * Returns the 8-bit IPv4 option type byte for a typed option kind.
 */
export function getIPv4OptionTypeByte(kind: IPv4Option['kind'], rawOptionType = 0): number {
  switch (kind) {
    case 'eol':
      return IPV4_OPT_EOL;
    case 'nop':
      return IPV4_OPT_NOP;
    case 'rr':
      return IPV4_OPT_RR;
    case 'timestamp':
      return IPV4_OPT_TIMESTAMP;
    case 'lsrr':
      return IPV4_OPT_LSRR;
    case 'ssrr':
      return IPV4_OPT_SSRR;
    case 'routerAlert':
      return IPV4_OPT_ROUTER_ALERT;
    case 'raw':
      return rawOptionType;
  }
}

export const IPV4_FIELD_SPANS: readonly RelativeFieldSpan[] = [
  { fieldId: 'version', label: 'Version (4)', bitOffset: 0, bitLength: 4 },
  { fieldId: 'ihl', label: 'IHL', bitOffset: 4, bitLength: 4 },
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

/**
 * Estimates the unpadded byte length of a single IPv4 option.
 */
export function getIPv4OptionByteLength(opt: IPv4Option): number {
  switch (opt.kind) {
    case 'eol':
    case 'nop':
      return 1;
    case 'rr':
    case 'lsrr':
    case 'ssrr':
      return 3 + opt.addresses.length * 4;
    case 'timestamp': {
      const parsed = parseHexBytes(opt.dataHex);
      return 4 + (parsed.ok ? parsed.value.length : 0);
    }
    case 'routerAlert':
      return 4;
    case 'raw': {
      const parsed = parseHexBytes(opt.dataHex);
      const dataLen = parsed.ok ? parsed.value.length : 0;
      return (opt.length.mode === 'none' ? 1 : 2) + dataLen;
    }
  }
}

/**
 * Computes raw (unpadded) and zero-padded option byte counts and IHL for an IPv4 options list.
 */
export function getIPv4OptionsMetrics(options: readonly IPv4Option[]): {
  readonly rawBytes: number;
  readonly paddingBytes: number;
  readonly paddedBytes: number;
  readonly ihl: number;
} {
  let rawBytes = 0;
  for (const opt of options) {
    rawBytes += getIPv4OptionByteLength(opt);
  }
  const paddingBytes = (4 - (rawBytes % 4)) % 4;
  const paddedBytes = rawBytes + paddingBytes;
  const ihl = IPV4_IHL + paddedBytes / 4;
  return { rawBytes, paddingBytes, paddedBytes, ihl };
}

/**
 * Returns the padded IPv4 header length in bytes (clamped to 20..60 for error-placeholder sizing).
 */
export function getIPv4HeaderLength(layer: IPv4Layer): number {
  const { paddedBytes } = getIPv4OptionsMetrics(layer.options);
  return IPV4_HEADER_LENGTH + Math.min(paddedBytes, IPV4_MAX_OPTIONS_LENGTH);
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
    case 'ipv6':
      return IP_PROTOCOL_IPV6;
    case 'gre':
      return IP_PROTOCOL_GRE;
    default:
      return null;
  }
}

/**
 * Encodes an IPv4 header with optional IPv4 options and 32-bit zero padding (RFC 791 §3.1).
 */
export function encodeIPv4(layer: IPv4Layer, ctx: EncodeIPv4Context): LayerEncodeResult {
  const errors: PacketError[] = [];
  const warnings: PacketWarning[] = [];
  const resolvedAutoValues: Record<string, number> = {};

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

  // Encode IPv4 options in order
  const optionBytes: number[] = [];
  const optionSpans: RelativeFieldSpan[] = [];
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
          'IPv4 options contain bytes after End of Option List (Type 0); receivers stop parsing options at EOL (RFC 791 §3.1).',
      });
      warnedAfterEol = true;
    }

    const pushTypeByteSpans = (typeByte: number, kindKey: string, shortName: string) => {
      const startBit = (IPV4_HEADER_LENGTH + optionBytes.length - 1) * 8;
      const parts = decodeIPv4OptionTypeByte(typeByte);
      optionSpans.push(
        {
          fieldId: `${optPrefix}.copied`,
          label: `Opt #${optNum}: Copied (${parts.copied})`,
          bitOffset: startBit,
          bitLength: 1,
        },
        {
          fieldId: `${optPrefix}.class`,
          label: `Opt #${optNum}: Class (${parts.optionClass})`,
          bitOffset: startBit + 1,
          bitLength: 2,
        },
        {
          fieldId: `${optPrefix}.${kindKey}.number`,
          label: `Opt #${optNum}: ${shortName} Num (${parts.number})`,
          bitOffset: startBit + 3,
          bitLength: 5,
        },
      );
    };

    const pushByteSpan = (fieldId: string, label: string, byteLength: number) => {
      const bitOffset = (IPV4_HEADER_LENGTH + optionBytes.length - byteLength) * 8;
      optionSpans.push({
        fieldId,
        label,
        bitOffset,
        bitLength: byteLength * 8,
      });
    };

    const pushBitsSpan = (fieldId: string, label: string, bitOffset: number, bitLength: number) => {
      optionSpans.push({ fieldId, label, bitOffset, bitLength });
    };

    switch (opt.kind) {
      case 'eol': {
        seenEol = true;
        optionBytes.push(IPV4_OPT_EOL);
        pushTypeByteSpans(IPV4_OPT_EOL, 'eol', 'EOL');
        break;
      }

      case 'nop': {
        optionBytes.push(IPV4_OPT_NOP);
        pushTypeByteSpans(IPV4_OPT_NOP, 'nop', 'NOP');
        break;
      }

      case 'rr':
      case 'lsrr':
      case 'ssrr': {
        const typeByte = getIPv4OptionTypeByte(opt.kind);
        const shortName = opt.kind === 'rr' ? 'RR' : opt.kind === 'lsrr' ? 'LSRR' : 'SSRR';
        const routeLen = 3 + opt.addresses.length * 4;

        if (opt.kind === 'lsrr') {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.lsrr.number`,
            message:
              'Loose Source and Record Route (Type 131) is commonly dropped by routers for security (RFC 7126 §4.3).',
          });
        } else if (opt.kind === 'ssrr') {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.ssrr.number`,
            message:
              'Strict Source and Record Route (Type 137) is commonly dropped by routers for security (RFC 7126 §4.4).',
          });
        }

        const autoPointer = 4;
        resolvedAutoValues[`${optPrefix}.${opt.kind}.pointer`] = autoPointer;
        let pointerVal = autoPointer;
        if (opt.pointer.mode === 'manual') {
          const ptrErr = validateUintRange(opt.pointer.value, 0xff, 'Pointer');
          if (ptrErr !== null) {
            errors.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.${opt.kind}.pointer`,
              message: ptrErr,
            });
          } else {
            pointerVal = opt.pointer.value;
            if (pointerVal < 4 || (pointerVal - 4) % 4 !== 0) {
              warnings.push({
                layerIndex: ctx.layerIndex,
                fieldId: `${optPrefix}.${opt.kind}.pointer`,
                message: `Pointer (${pointerVal}) must be >= 4 and of the form 4 + 4k per RFC 791 §3.1.`,
              });
            }
          }
        }

        if (routeLen > 0xff) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.${opt.kind}.length`,
            message: `${shortName} option length (${routeLen} bytes) exceeds 255 bytes.`,
          });
        }

        optionBytes.push(typeByte);
        pushTypeByteSpans(typeByte, opt.kind, shortName);
        optionBytes.push(routeLen & 0xff);
        pushByteSpan(`${optPrefix}.${opt.kind}.length`, `Opt #${optNum}: ${shortName} Len (${routeLen})`, 1);
        optionBytes.push(pointerVal & 0xff);
        pushByteSpan(`${optPrefix}.${opt.kind}.pointer`, `Opt #${optNum}: ${shortName} Ptr`, 1);

        for (let a = 0; a < opt.addresses.length; a++) {
          const addrFieldId = `${optPrefix}.${opt.kind}.addrs[${a}]`;
          const parsedAddr = parseIPv4(opt.addresses[a]);
          if (!parsedAddr.ok) {
            errors.push({
              layerIndex: ctx.layerIndex,
              fieldId: addrFieldId,
              message: parsedAddr.error,
            });
            optionBytes.push(0, 0, 0, 0);
          } else {
            optionBytes.push(
              parsedAddr.value[0],
              parsedAddr.value[1],
              parsedAddr.value[2],
              parsedAddr.value[3],
            );
          }
          pushByteSpan(addrFieldId, `Opt #${optNum}: ${shortName} IP #${a + 1}`, 4);
        }
        break;
      }

      case 'timestamp': {
        const ptrErr = validateUintRange(opt.pointer, 0xff, 'Pointer');
        if (ptrErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamp.pointer`,
            message: ptrErr,
          });
        }
        const ovflErr = validateUintRange(opt.overflow, 0x0f, 'Overflow');
        if (ovflErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamp.overflow`,
            message: ovflErr,
          });
        }
        const flagErr = validateUintRange(opt.flag, 0x0f, 'Flag');
        if (flagErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamp.flag`,
            message: flagErr,
          });
        }
        const dataParsed = parseHexBytes(opt.dataHex);
        if (!dataParsed.ok) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamp.data`,
            message: dataParsed.error,
          });
        }
        const dataBytes = dataParsed.ok ? dataParsed.value : new Uint8Array(0);
        const tsLen = 4 + dataBytes.length;
        if (tsLen > 0xff) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.timestamp.length`,
            message: `Internet Timestamp option length (${tsLen} bytes) exceeds 255 bytes.`,
          });
        }

        optionBytes.push(IPV4_OPT_TIMESTAMP);
        pushTypeByteSpans(IPV4_OPT_TIMESTAMP, 'timestamp', 'TS');
        optionBytes.push(tsLen & 0xff);
        pushByteSpan(`${optPrefix}.timestamp.length`, `Opt #${optNum}: TS Len (${tsLen})`, 1);
        optionBytes.push(ptrErr === null ? opt.pointer : 0);
        pushByteSpan(`${optPrefix}.timestamp.pointer`, `Opt #${optNum}: TS Ptr`, 1);

        const ovflFlagByte =
          ((ovflErr === null ? opt.overflow : 0) << 4) | (flagErr === null ? opt.flag : 0);
        const ovflBitOffset = (IPV4_HEADER_LENGTH + optionBytes.length) * 8;
        optionBytes.push(ovflFlagByte);
        pushBitsSpan(`${optPrefix}.timestamp.overflow`, `Opt #${optNum}: TS Oflw`, ovflBitOffset, 4);
        pushBitsSpan(`${optPrefix}.timestamp.flag`, `Opt #${optNum}: TS Flag`, ovflBitOffset + 4, 4);

        if (dataBytes.length > 0) {
          for (let d = 0; d < dataBytes.length; d++) {
            optionBytes.push(dataBytes[d]);
          }
          pushByteSpan(`${optPrefix}.timestamp.data`, `Opt #${optNum}: TS Data`, dataBytes.length);
        }
        break;
      }

      case 'routerAlert': {
        const valErr = validateUintRange(opt.value, 0xffff, 'Router Alert Value');
        if (valErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.routerAlert.value`,
            message: valErr,
          });
        } else if (opt.value !== 0) {
          warnings.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.routerAlert.value`,
            message: `Router Alert value is ${opt.value}; RFC 2113 §2.1 defines value 0 ("Router shall examine packet").`,
          });
        }

        const val = valErr === null ? opt.value : 0;
        optionBytes.push(IPV4_OPT_ROUTER_ALERT);
        pushTypeByteSpans(IPV4_OPT_ROUTER_ALERT, 'routerAlert', 'RA');
        optionBytes.push(4);
        pushByteSpan(`${optPrefix}.routerAlert.length`, `Opt #${optNum}: RA Len (4)`, 1);
        optionBytes.push((val >>> 8) & 0xff, val & 0xff);
        pushByteSpan(`${optPrefix}.routerAlert.value`, `Opt #${optNum}: RA Value`, 2);
        break;
      }

      case 'raw': {
        const typeErr = validateUintRange(opt.optionType, 0xff, 'Option Type');
        if (typeErr !== null) {
          errors.push({
            layerIndex: ctx.layerIndex,
            fieldId: `${optPrefix}.raw.number`,
            message: typeErr,
          });
        } else {
          if (opt.optionType === IPV4_OPT_EOL) {
            seenEol = true;
          }
          if (
            (opt.optionType === IPV4_OPT_EOL || opt.optionType === IPV4_OPT_NOP) &&
            opt.length.mode !== 'none'
          ) {
            warnings.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: `IPv4 option Type ${opt.optionType} (${opt.optionType === IPV4_OPT_EOL ? 'EOL' : 'NOP'}) is a 1-byte option without a Length field (RFC 791 §3.1).`,
            });
          }
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

        const typeVal = typeErr === null ? opt.optionType : 0;
        optionBytes.push(typeVal);
        pushTypeByteSpans(typeVal, 'raw', 'Raw');

        if (opt.length.mode === 'auto') {
          if (autoLen > 0xff) {
            errors.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: `Auto IPv4 option Length (${autoLen}) exceeds the 255-byte 8-bit limit (RFC 791 §3.1).`,
            });
          }
          optionBytes.push(autoLen & 0xff);
          pushByteSpan(`${optPrefix}.raw.length`, `Opt #${optNum}: Raw Len (${autoLen})`, 1);
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
              message: `IPv4 option Length must be at least 2 (got ${opt.length.value}, RFC 791 §3.1).`,
            });
          } else if (dataParsed.ok && opt.length.value !== autoLen) {
            warnings.push({
              layerIndex: ctx.layerIndex,
              fieldId: `${optPrefix}.raw.length`,
              message: `Manual IPv4 option Length (${opt.length.value}) differs from actual encoded length (${autoLen} bytes).`,
            });
          }
          optionBytes.push(lenErr === null ? opt.length.value : 0);
          pushByteSpan(
            `${optPrefix}.raw.length`,
            `Opt #${optNum}: Raw Len (${lenErr === null ? opt.length.value : '?'})`,
            1,
          );
        }

        if (dataBytes.length > 0) {
          for (let d = 0; d < dataBytes.length; d++) {
            optionBytes.push(dataBytes[d]);
          }
          pushByteSpan(`${optPrefix}.raw.data`, `Opt #${optNum}: Raw Data`, dataBytes.length);
        }
        break;
      }
    }
  }

  const rawOptionsLen = optionBytes.length;
  const paddingLen = (4 - (rawOptionsLen % 4)) % 4;
  const paddedOptionsLen = rawOptionsLen + paddingLen;
  const autoIhl = IPV4_IHL + paddedOptionsLen / 4;

  if (rawOptionsLen > IPV4_MAX_OPTIONS_LENGTH) {
    errors.push({
      layerIndex: ctx.layerIndex,
      fieldId: 'options',
      message: `IPv4 options exceed the ${IPV4_MAX_OPTIONS_LENGTH}-byte maximum (got ${rawOptionsLen} bytes; IHL cannot exceed ${IPV4_MAX_IHL} per RFC 791 §3.1).`,
    });
  }

  if (paddingLen > 0) {
    optionSpans.push({
      fieldId: 'optionsPadding',
      label: 'Options Padding',
      bitOffset: (IPV4_HEADER_LENGTH + rawOptionsLen) * 8,
      bitLength: paddingLen * 8,
    });
  }

  const headerLength = IPV4_HEADER_LENGTH + paddedOptionsLen;

  let ihlValue = autoIhl;
  if (layer.ihl.mode === 'manual') {
    const ihlErr = validateUintRange(layer.ihl.value, IPV4_MAX_IHL, 'IHL');
    if (ihlErr !== null) {
      errors.push({ layerIndex: ctx.layerIndex, fieldId: 'ihl', message: ihlErr });
    } else {
      ihlValue = layer.ihl.value;
      if (ihlValue < IPV4_IHL) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'ihl',
          message: `Manual IHL (${ihlValue}) is smaller than the minimum of 5 (RFC 791 §3.1).`,
        });
      } else if (ihlValue !== autoIhl) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'ihl',
          message: `Using manual IHL ${ihlValue} (computed value is ${autoIhl} for ${headerLength}-byte header).`,
        });
      }
    }
  }

  // RFC 791 Section 3.1: Total Length is 16-bit (max 65535 bytes)
  const actualTotalLength = headerLength + ctx.upperBytesLength;
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
      if (totalLengthValue < headerLength) {
        warnings.push({
          layerIndex: ctx.layerIndex,
          fieldId: 'totalLength',
          message: `Manual Total Length (${totalLengthValue}) is smaller than the ${headerLength}-byte IPv4 header (RFC 791).`,
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
      message: 'No ICMP / IPv4 / IPv6 / GRE / TCP / UDP upper layer found; defaulting Protocol to 0.',
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

  const header = new Uint8Array(headerLength);
  header[0] = (IPV4_VERSION << 4) | (ihlValue & 0x0f);
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
  for (let i = 0; i < optionBytes.length; i++) {
    header[IPV4_HEADER_LENGTH + i] = optionBytes[i];
  }
  // Trailing padding bytes (if any) remain 0

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

  resolvedAutoValues.ihl = autoIhl;
  resolvedAutoValues.totalLength = actualTotalLength;
  resolvedAutoValues.protocol = autoProtocol;
  resolvedAutoValues.headerChecksum = autoChecksum;

  return {
    ok: true,
    bytes: header,
    spans: optionSpans.length > 0 ? [...IPV4_FIELD_SPANS, ...optionSpans] : IPV4_FIELD_SPANS,
    warnings,
    resolvedAutoValues,
  };
}
