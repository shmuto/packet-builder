import { decodeUtf8Strict, encodeUtf8, parseHexBytes } from './bytes';
import type {
  ARPLayer,
  AutoOrManual,
  BGPLayer,
  BGPMessageType,
  EthernetLayer,
  ICMPLayer,
  ICMPv6Layer,
  ICMPv6Rest,
  IPv4Flags,
  IPv4Layer,
  IPv6Layer,
  Layer,
  TCPFlags,
  TCPLayer,
  UDPLayer,
} from './layers/types';
import { err, ok, type Result } from './result';

export const PERMALINK_VERSION = 1;
export const PERMALINK_PREFIX = `p${PERMALINK_VERSION}=`;
export const MAX_PERMALINK_LAYERS = 64;
export const MAX_PERMALINK_PAYLOAD_BYTES = 65535;
export const PERMALINK_LONG_URL_THRESHOLD = 8000;

export type PermalinkPayload =
  | { readonly mode: 'text'; readonly text: string }
  | { readonly mode: 'hex'; readonly hex: string };

export interface PermalinkState {
  readonly layers: readonly Layer[];
  readonly payload: PermalinkPayload;
}

const FRAGMENT_VERSION_PATTERN = /^p([0-9]+)=(.*)$/s;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function bytesToBase64Url(bytes: Uint8Array): string {
  // Convert in chunks to avoid call stack limits on large payloads (up to 65535 bytes)
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    let chunk = '';
    for (let j = 0; j < slice.length; j++) {
      chunk += String.fromCharCode(slice[j]);
    }
    binary += chunk;
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(encoded: string): Result<Uint8Array> {
  if (encoded.length === 0) {
    return err('Permalink data is empty.');
  }
  if (!BASE64URL_PATTERN.test(encoded) || encoded.length % 4 === 1) {
    return err('Invalid base64url encoding in permalink.');
  }
  const padded =
    encoded.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (encoded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return err('Invalid base64url encoding in permalink.');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return ok(bytes);
}

/**
 * Encodes a packet builder state into a versioned URL fragment (`p1=<base64url(UTF-8 JSON)>`).
 */
export function encodePermalink(state: PermalinkState): string {
  const canonical: PermalinkState = {
    layers: state.layers,
    payload: state.payload,
  };
  const json = JSON.stringify(canonical);
  return `${PERMALINK_PREFIX}${bytesToBase64Url(encodeUtf8(json))}`;
}

/**
 * Builds a full shareable URL that preserves any sub-path (such as GitHub Pages `/repo/`).
 */
export function buildPermalinkUrl(origin: string, pathname: string, fragment: string): string {
  const normalized = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  return `${origin}${pathname}#${normalized}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateExactKeys(
  value: unknown,
  expectedKeys: readonly string[],
  context: string,
): Result<Record<string, unknown>> {
  if (!isPlainObject(value)) {
    return err(`${context} must be an object.`);
  }
  const ownKeys = Object.keys(value);
  for (const key of ownKeys) {
    if (FORBIDDEN_KEYS.has(key)) {
      return err(`${context} contains forbidden key "${key}".`);
    }
  }
  const expectedSet = new Set(expectedKeys);
  for (const key of ownKeys) {
    if (!expectedSet.has(key)) {
      return err(`${context} has unexpected key "${key}".`);
    }
  }
  for (const key of expectedKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      return err(`${context} is missing required key "${key}".`);
    }
  }
  return ok(value);
}

function expectString(obj: Record<string, unknown>, key: string, context: string): Result<string> {
  const value = obj[key];
  if (typeof value !== 'string') {
    return err(`${context}.${key} must be a string.`);
  }
  return ok(value);
}

function expectNumber(obj: Record<string, unknown>, key: string, context: string): Result<number> {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return err(`${context}.${key} must be a finite number.`);
  }
  return ok(value);
}

function expectBoolean(
  obj: Record<string, unknown>,
  key: string,
  context: string,
): Result<boolean> {
  const value = obj[key];
  if (typeof value !== 'boolean') {
    return err(`${context}.${key} must be a boolean.`);
  }
  return ok(value);
}

function validateAutoOrManualNumber(
  raw: unknown,
  context: string,
): Result<AutoOrManual<number>> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const mode = raw.mode;
  if (mode === 'auto') {
    const checked = validateExactKeys(raw, ['mode'], context);
    if (!checked.ok) return checked;
    return ok({ mode: 'auto' });
  }
  if (mode === 'manual') {
    const checked = validateExactKeys(raw, ['mode', 'value'], context);
    if (!checked.ok) return checked;
    const val = expectNumber(checked.value, 'value', context);
    if (!val.ok) return val;
    return ok({ mode: 'manual', value: val.value });
  }
  return err(`${context}.mode must be "auto" or "manual".`);
}

function validateAutoOrManualString(
  raw: unknown,
  context: string,
): Result<AutoOrManual<string>> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const mode = raw.mode;
  if (mode === 'auto') {
    const checked = validateExactKeys(raw, ['mode'], context);
    if (!checked.ok) return checked;
    return ok({ mode: 'auto' });
  }
  if (mode === 'manual') {
    const checked = validateExactKeys(raw, ['mode', 'value'], context);
    if (!checked.ok) return checked;
    const val = expectString(checked.value, 'value', context);
    if (!val.ok) return val;
    return ok({ mode: 'manual', value: val.value });
  }
  return err(`${context}.mode must be "auto" or "manual".`);
}

function validateIPv4Flags(raw: unknown, context: string): Result<IPv4Flags> {
  const checked = validateExactKeys(raw, ['reserved', 'df', 'mf'], context);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const reserved = expectBoolean(obj, 'reserved', context);
  if (!reserved.ok) return reserved;
  const df = expectBoolean(obj, 'df', context);
  if (!df.ok) return df;
  const mf = expectBoolean(obj, 'mf', context);
  if (!mf.ok) return mf;
  return ok({ reserved: reserved.value, df: df.value, mf: mf.value });
}

function validateTCPFlags(raw: unknown, context: string): Result<TCPFlags> {
  const checked = validateExactKeys(
    raw,
    ['cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin'],
    context,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const cwr = expectBoolean(obj, 'cwr', context);
  if (!cwr.ok) return cwr;
  const ece = expectBoolean(obj, 'ece', context);
  if (!ece.ok) return ece;
  const urg = expectBoolean(obj, 'urg', context);
  if (!urg.ok) return urg;
  const ack = expectBoolean(obj, 'ack', context);
  if (!ack.ok) return ack;
  const psh = expectBoolean(obj, 'psh', context);
  if (!psh.ok) return psh;
  const rst = expectBoolean(obj, 'rst', context);
  if (!rst.ok) return rst;
  const syn = expectBoolean(obj, 'syn', context);
  if (!syn.ok) return syn;
  const fin = expectBoolean(obj, 'fin', context);
  if (!fin.ok) return fin;
  return ok({
    cwr: cwr.value,
    ece: ece.value,
    urg: urg.value,
    ack: ack.value,
    psh: psh.value,
    rst: rst.value,
    syn: syn.value,
    fin: fin.value,
  });
}

function validateEthernetLayer(raw: Record<string, unknown>, ctx: string): Result<EthernetLayer> {
  const checked = validateExactKeys(raw, ['type', 'dstMac', 'srcMac', 'etherType'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const dstMac = expectString(obj, 'dstMac', ctx);
  if (!dstMac.ok) return dstMac;
  const srcMac = expectString(obj, 'srcMac', ctx);
  if (!srcMac.ok) return srcMac;
  const etherType = validateAutoOrManualNumber(obj.etherType, `${ctx}.etherType`);
  if (!etherType.ok) return etherType;
  return ok({
    type: 'ethernet',
    dstMac: dstMac.value,
    srcMac: srcMac.value,
    etherType: etherType.value,
  });
}

function validateARPLayer(raw: Record<string, unknown>, ctx: string): Result<ARPLayer> {
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

function validateIPv4Layer(raw: Record<string, unknown>, ctx: string): Result<IPv4Layer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'tos',
      'totalLength',
      'identification',
      'flags',
      'fragmentOffset',
      'ttl',
      'protocol',
      'headerChecksum',
      'srcIp',
      'dstIp',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const tos = expectNumber(obj, 'tos', ctx);
  if (!tos.ok) return tos;
  const totalLength = validateAutoOrManualNumber(obj.totalLength, `${ctx}.totalLength`);
  if (!totalLength.ok) return totalLength;
  const identification = expectNumber(obj, 'identification', ctx);
  if (!identification.ok) return identification;
  const flags = validateIPv4Flags(obj.flags, `${ctx}.flags`);
  if (!flags.ok) return flags;
  const fragmentOffset = expectNumber(obj, 'fragmentOffset', ctx);
  if (!fragmentOffset.ok) return fragmentOffset;
  const ttl = expectNumber(obj, 'ttl', ctx);
  if (!ttl.ok) return ttl;
  const protocol = validateAutoOrManualNumber(obj.protocol, `${ctx}.protocol`);
  if (!protocol.ok) return protocol;
  const headerChecksum = validateAutoOrManualNumber(obj.headerChecksum, `${ctx}.headerChecksum`);
  if (!headerChecksum.ok) return headerChecksum;
  const srcIp = expectString(obj, 'srcIp', ctx);
  if (!srcIp.ok) return srcIp;
  const dstIp = expectString(obj, 'dstIp', ctx);
  if (!dstIp.ok) return dstIp;
  return ok({
    type: 'ipv4',
    tos: tos.value,
    totalLength: totalLength.value,
    identification: identification.value,
    flags: flags.value,
    fragmentOffset: fragmentOffset.value,
    ttl: ttl.value,
    protocol: protocol.value,
    headerChecksum: headerChecksum.value,
    srcIp: srcIp.value,
    dstIp: dstIp.value,
  });
}

function validateIPv6Layer(raw: Record<string, unknown>, ctx: string): Result<IPv6Layer> {
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

function validateICMPLayer(raw: Record<string, unknown>, ctx: string): Result<ICMPLayer> {
  const checked = validateExactKeys(
    raw,
    ['type', 'icmpType', 'code', 'checksum', 'identifier', 'sequenceNumber'],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const icmpType = expectNumber(obj, 'icmpType', ctx);
  if (!icmpType.ok) return icmpType;
  const code = expectNumber(obj, 'code', ctx);
  if (!code.ok) return code;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const identifier = expectNumber(obj, 'identifier', ctx);
  if (!identifier.ok) return identifier;
  const sequenceNumber = expectNumber(obj, 'sequenceNumber', ctx);
  if (!sequenceNumber.ok) return sequenceNumber;
  return ok({
    type: 'icmp',
    icmpType: icmpType.value,
    code: code.value,
    checksum: checksum.value,
    identifier: identifier.value,
    sequenceNumber: sequenceNumber.value,
  });
}

function validateICMPv6Rest(raw: unknown, context: string): Result<ICMPv6Rest> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const kind = raw.kind;
  if (kind === 'echo') {
    const checked = validateExactKeys(raw, ['kind', 'identifier', 'sequence'], context);
    if (!checked.ok) return checked;
    const identifier = expectNumber(checked.value, 'identifier', context);
    if (!identifier.ok) return identifier;
    const sequence = expectNumber(checked.value, 'sequence', context);
    if (!sequence.ok) return sequence;
    return ok({ kind: 'echo', identifier: identifier.value, sequence: sequence.value });
  }
  if (kind === 'raw') {
    const checked = validateExactKeys(raw, ['kind', 'value'], context);
    if (!checked.ok) return checked;
    const value = expectNumber(checked.value, 'value', context);
    if (!value.ok) return value;
    return ok({ kind: 'raw', value: value.value });
  }
  return err(`${context}.kind must be "echo" or "raw".`);
}

function validateICMPv6Layer(raw: Record<string, unknown>, ctx: string): Result<ICMPv6Layer> {
  const checked = validateExactKeys(
    raw,
    ['type', 'icmpType', 'code', 'checksum', 'rest'],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const icmpType = expectNumber(obj, 'icmpType', ctx);
  if (!icmpType.ok) return icmpType;
  const code = expectNumber(obj, 'code', ctx);
  if (!code.ok) return code;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const rest = validateICMPv6Rest(obj.rest, `${ctx}.rest`);
  if (!rest.ok) return rest;
  return ok({
    type: 'icmpv6',
    icmpType: icmpType.value,
    code: code.value,
    checksum: checksum.value,
    rest: rest.value,
  });
}

function validateUDPLayer(raw: Record<string, unknown>, ctx: string): Result<UDPLayer> {
  const checked = validateExactKeys(
    raw,
    ['type', 'srcPort', 'dstPort', 'length', 'checksum'],
    ctx,
  );
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

function validateTCPLayer(raw: Record<string, unknown>, ctx: string): Result<TCPLayer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'srcPort',
      'dstPort',
      'seqNumber',
      'ackNumber',
      'dataOffset',
      'flags',
      'windowSize',
      'checksum',
      'urgentPointer',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const srcPort = expectNumber(obj, 'srcPort', ctx);
  if (!srcPort.ok) return srcPort;
  const dstPort = expectNumber(obj, 'dstPort', ctx);
  if (!dstPort.ok) return dstPort;
  const seqNumber = expectNumber(obj, 'seqNumber', ctx);
  if (!seqNumber.ok) return seqNumber;
  const ackNumber = expectNumber(obj, 'ackNumber', ctx);
  if (!ackNumber.ok) return ackNumber;
  const dataOffset = validateAutoOrManualNumber(obj.dataOffset, `${ctx}.dataOffset`);
  if (!dataOffset.ok) return dataOffset;
  const flags = validateTCPFlags(obj.flags, `${ctx}.flags`);
  if (!flags.ok) return flags;
  const windowSize = expectNumber(obj, 'windowSize', ctx);
  if (!windowSize.ok) return windowSize;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const urgentPointer = expectNumber(obj, 'urgentPointer', ctx);
  if (!urgentPointer.ok) return urgentPointer;
  return ok({
    type: 'tcp',
    srcPort: srcPort.value,
    dstPort: dstPort.value,
    seqNumber: seqNumber.value,
    ackNumber: ackNumber.value,
    dataOffset: dataOffset.value,
    flags: flags.value,
    windowSize: windowSize.value,
    checksum: checksum.value,
    urgentPointer: urgentPointer.value,
  });
}

function validateBGPLayer(raw: Record<string, unknown>, ctx: string): Result<BGPLayer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'bgpType',
      'marker',
      'length',
      'version',
      'myAs',
      'holdTime',
      'bgpIdentifier',
      'optParamLength',
      'withdrawnRoutesLength',
      'totalPathAttrLength',
      'errorCode',
      'errorSubcode',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const bgpTypeRaw = obj.bgpType;
  if (bgpTypeRaw !== 1 && bgpTypeRaw !== 2 && bgpTypeRaw !== 3 && bgpTypeRaw !== 4) {
    return err(`${ctx}.bgpType must be 1, 2, 3, or 4.`);
  }
  const bgpType: BGPMessageType = bgpTypeRaw;
  const marker = validateAutoOrManualString(obj.marker, `${ctx}.marker`);
  if (!marker.ok) return marker;
  const length = validateAutoOrManualNumber(obj.length, `${ctx}.length`);
  if (!length.ok) return length;
  const version = validateAutoOrManualNumber(obj.version, `${ctx}.version`);
  if (!version.ok) return version;
  const myAs = expectNumber(obj, 'myAs', ctx);
  if (!myAs.ok) return myAs;
  const holdTime = expectNumber(obj, 'holdTime', ctx);
  if (!holdTime.ok) return holdTime;
  const bgpIdentifier = expectString(obj, 'bgpIdentifier', ctx);
  if (!bgpIdentifier.ok) return bgpIdentifier;
  const optParamLength = validateAutoOrManualNumber(obj.optParamLength, `${ctx}.optParamLength`);
  if (!optParamLength.ok) return optParamLength;
  const withdrawnRoutesLength = validateAutoOrManualNumber(
    obj.withdrawnRoutesLength,
    `${ctx}.withdrawnRoutesLength`,
  );
  if (!withdrawnRoutesLength.ok) return withdrawnRoutesLength;
  const totalPathAttrLength = validateAutoOrManualNumber(
    obj.totalPathAttrLength,
    `${ctx}.totalPathAttrLength`,
  );
  if (!totalPathAttrLength.ok) return totalPathAttrLength;
  const errorCode = expectNumber(obj, 'errorCode', ctx);
  if (!errorCode.ok) return errorCode;
  const errorSubcode = expectNumber(obj, 'errorSubcode', ctx);
  if (!errorSubcode.ok) return errorSubcode;
  return ok({
    type: 'bgp',
    bgpType,
    marker: marker.value,
    length: length.value,
    version: version.value,
    myAs: myAs.value,
    holdTime: holdTime.value,
    bgpIdentifier: bgpIdentifier.value,
    optParamLength: optParamLength.value,
    withdrawnRoutesLength: withdrawnRoutesLength.value,
    totalPathAttrLength: totalPathAttrLength.value,
    errorCode: errorCode.value,
    errorSubcode: errorSubcode.value,
  });
}

function validateLayer(raw: unknown, index: number): Result<Layer> {
  const ctx = `layers[${index}]`;
  if (!isPlainObject(raw)) {
    return err(`${ctx} must be an object.`);
  }
  const type = raw.type;
  if (typeof type !== 'string') {
    return err(`${ctx}.type must be a string.`);
  }
  switch (type) {
    case 'ethernet':
      return validateEthernetLayer(raw, ctx);
    case 'arp':
      return validateARPLayer(raw, ctx);
    case 'ipv4':
      return validateIPv4Layer(raw, ctx);
    case 'ipv6':
      return validateIPv6Layer(raw, ctx);
    case 'icmp':
      return validateICMPLayer(raw, ctx);
    case 'icmpv6':
      return validateICMPv6Layer(raw, ctx);
    case 'udp':
      return validateUDPLayer(raw, ctx);
    case 'tcp':
      return validateTCPLayer(raw, ctx);
    case 'bgp':
      return validateBGPLayer(raw, ctx);
    default:
      return err(`${ctx} has unknown layer type "${type}".`);
  }
}

function validatePayload(raw: unknown): Result<PermalinkPayload> {
  const ctx = 'payload';
  if (!isPlainObject(raw)) {
    return err(`${ctx} must be an object.`);
  }
  const mode = raw.mode;
  if (mode === 'text') {
    const checked = validateExactKeys(raw, ['mode', 'text'], ctx);
    if (!checked.ok) return checked;
    const text = expectString(checked.value, 'text', ctx);
    if (!text.ok) return text;
    const byteLength = encodeUtf8(text.value).length;
    if (byteLength > MAX_PERMALINK_PAYLOAD_BYTES) {
      return err(
        `Decoded text payload exceeds maximum of ${MAX_PERMALINK_PAYLOAD_BYTES} bytes (got ${byteLength} bytes).`,
      );
    }
    return ok({ mode: 'text', text: text.value });
  }
  if (mode === 'hex') {
    const checked = validateExactKeys(raw, ['mode', 'hex'], ctx);
    if (!checked.ok) return checked;
    const hex = expectString(checked.value, 'hex', ctx);
    if (!hex.ok) return hex;
    const parsed = parseHexBytes(hex.value);
    if (parsed.ok) {
      if (parsed.value.length > MAX_PERMALINK_PAYLOAD_BYTES) {
        return err(
          `Decoded hex payload exceeds maximum of ${MAX_PERMALINK_PAYLOAD_BYTES} bytes (got ${parsed.value.length} bytes).`,
        );
      }
    } else {
      // Allow intentionally malformed hex strings to load so the normal payload error UI reports them,
      // while still bounding raw non-whitespace characters to the max payload budget.
      const compactLength = hex.value.replace(/\s+/g, '').length;
      if (compactLength > MAX_PERMALINK_PAYLOAD_BYTES * 2) {
        return err(
          `Hex payload exceeds maximum length for ${MAX_PERMALINK_PAYLOAD_BYTES} bytes.`,
        );
      }
    }
    return ok({ mode: 'hex', hex: hex.value });
  }
  return err(`${ctx}.mode must be "text" or "hex".`);
}

/**
 * Decodes and validates a permalink fragment (`p1=...` or `#p1=...`).
 * Never throws; returns `err` with a descriptive message on malformed or unsupported inputs.
 * Validates schema shape and safety limits only—out-of-range or malformed field values
 * load as-is so `buildPacket` surfaces them through the normal error UI.
 */
export function decodePermalink(fragment: string): Result<PermalinkState> {
  const normalized = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const match = FRAGMENT_VERSION_PATTERN.exec(normalized);
  if (!match) {
    return err(`Invalid permalink format: expected "${PERMALINK_PREFIX}<data>".`);
  }
  const version = match[1];
  if (version !== String(PERMALINK_VERSION)) {
    return err(
      `Unsupported permalink version "p${version}" (only "p${PERMALINK_VERSION}" is supported).`,
    );
  }

  const decodedBytes = base64UrlToBytes(match[2]);
  if (!decodedBytes.ok) {
    return decodedBytes;
  }

  const utf8 = decodeUtf8Strict(decodedBytes.value);
  if (!utf8.ok) {
    return err(`Permalink contains invalid UTF-8 (${utf8.error})`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8.value);
  } catch {
    return err('Permalink contains invalid JSON.');
  }

  const root = validateExactKeys(parsed, ['layers', 'payload'], 'permalink');
  if (!root.ok) {
    return root;
  }

  const rawLayers = root.value.layers;
  if (!Array.isArray(rawLayers)) {
    return err('permalink.layers must be an array.');
  }
  if (rawLayers.length > MAX_PERMALINK_LAYERS) {
    return err(
      `Permalink exceeds maximum of ${MAX_PERMALINK_LAYERS} layers (got ${rawLayers.length}).`,
    );
  }

  const layers: Layer[] = [];
  for (let i = 0; i < rawLayers.length; i++) {
    const validated = validateLayer(rawLayers[i], i);
    if (!validated.ok) {
      return validated;
    }
    layers.push(validated.value);
  }

  const payload = validatePayload(root.value.payload);
  if (!payload.ok) {
    return payload;
  }

  return ok({ layers, payload: payload.value });
}

function containsNonFiniteNumber(value: unknown): boolean {
  if (typeof value === 'number') {
    return !Number.isFinite(value);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (containsNonFiniteNumber(value[i])) {
        return true;
      }
    }
    return false;
  }
  if (typeof value === 'object' && value !== null) {
    for (const entry of Object.values(value)) {
      if (containsNonFiniteNumber(entry)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Returns true if every numeric field across all layers is finite (not NaN/Infinity).
 * Used to avoid serializing transient blank numeric drafts (`NaN` -> JSON `null`) into the URL hash.
 */
export function hasOnlyFiniteNumbers(layers: readonly Layer[]): boolean {
  return !containsNonFiniteNumber(layers);
}
