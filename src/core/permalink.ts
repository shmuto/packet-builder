import { decodeUtf8Strict, encodeUtf8, parseHexBytes } from './bytes';
import type {
  ARPLayer,
  AutoOrManual,
  BGPLayer,
  BGPMessageType,
  EthernetLayer,
  GRELayer,
  ICMPLayer,
  ICMPv6Layer,
  ICMPv6Rest,
  IPv4Flags,
  IPv4Layer,
  IPv4Option,
  IPv6Layer,
  Layer,
  RawOptionLength,
  TCPFlags,
  TCPLayer,
  TCPOption,
  TCPSackBlock,
  UDPLayer,
  VLANLayer,
  VXLANLayer,
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

function validateVLANLayer(raw: Record<string, unknown>, ctx: string): Result<VLANLayer> {
  const checked = validateExactKeys(raw, ['type', 'pcp', 'dei', 'vid', 'etherType'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const pcp = expectNumber(obj, 'pcp', ctx);
  if (!pcp.ok) return pcp;
  const dei = expectBoolean(obj, 'dei', ctx);
  if (!dei.ok) return dei;
  const vid = expectNumber(obj, 'vid', ctx);
  if (!vid.ok) return vid;
  const etherType = validateAutoOrManualNumber(obj.etherType, `${ctx}.etherType`);
  if (!etherType.ok) return etherType;
  return ok({
    type: 'vlan',
    pcp: pcp.value,
    dei: dei.value,
    vid: vid.value,
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

function validateIPv4Option(raw: unknown, context: string): Result<IPv4Option> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const kind = raw.kind;
  if (typeof kind !== 'string') {
    return err(`${context}.kind must be a string.`);
  }
  switch (kind) {
    case 'eol': {
      const checked = validateExactKeys(raw, ['kind'], context);
      if (!checked.ok) return checked;
      return ok({ kind: 'eol' });
    }
    case 'nop': {
      const checked = validateExactKeys(raw, ['kind'], context);
      if (!checked.ok) return checked;
      return ok({ kind: 'nop' });
    }
    case 'rr':
    case 'lsrr':
    case 'ssrr': {
      const checked = validateExactKeys(raw, ['kind', 'pointer', 'addresses'], context);
      if (!checked.ok) return checked;
      const pointer = validateAutoOrManualNumber(checked.value.pointer, `${context}.pointer`);
      if (!pointer.ok) return pointer;
      const rawAddresses = checked.value.addresses;
      if (!Array.isArray(rawAddresses)) {
        return err(`${context}.addresses must be an array.`);
      }
      if (rawAddresses.length > MAX_PERMALINK_OPTION_ITEMS) {
        return err(
          `${context}.addresses exceeds maximum of ${MAX_PERMALINK_OPTION_ITEMS} items (got ${rawAddresses.length}).`,
        );
      }
      const addresses: string[] = [];
      for (let i = 0; i < rawAddresses.length; i++) {
        if (typeof rawAddresses[i] !== 'string') {
          return err(`${context}.addresses[${i}] must be a string.`);
        }
        addresses.push(rawAddresses[i]);
      }
      return ok({ kind, pointer: pointer.value, addresses });
    }
    case 'timestamp': {
      const checked = validateExactKeys(
        raw,
        ['kind', 'pointer', 'overflow', 'flag', 'dataHex'],
        context,
      );
      if (!checked.ok) return checked;
      const pointer = expectNumber(checked.value, 'pointer', context);
      if (!pointer.ok) return pointer;
      const overflow = expectNumber(checked.value, 'overflow', context);
      if (!overflow.ok) return overflow;
      const flag = expectNumber(checked.value, 'flag', context);
      if (!flag.ok) return flag;
      const dataHex = expectString(checked.value, 'dataHex', context);
      if (!dataHex.ok) return dataHex;
      return ok({
        kind: 'timestamp',
        pointer: pointer.value,
        overflow: overflow.value,
        flag: flag.value,
        dataHex: dataHex.value,
      });
    }
    case 'routerAlert': {
      const checked = validateExactKeys(raw, ['kind', 'value'], context);
      if (!checked.ok) return checked;
      const value = expectNumber(checked.value, 'value', context);
      if (!value.ok) return value;
      return ok({ kind: 'routerAlert', value: value.value });
    }
    case 'raw': {
      const checked = validateExactKeys(raw, ['kind', 'optionType', 'length', 'dataHex'], context);
      if (!checked.ok) return checked;
      const optionType = expectNumber(checked.value, 'optionType', context);
      if (!optionType.ok) return optionType;
      const length = validateRawOptionLength(checked.value.length, `${context}.length`);
      if (!length.ok) return length;
      const dataHex = expectString(checked.value, 'dataHex', context);
      if (!dataHex.ok) return dataHex;
      return ok({
        kind: 'raw',
        optionType: optionType.value,
        length: length.value,
        dataHex: dataHex.value,
      });
    }
    default:
      return err(`${context} has unknown IPv4 option kind "${kind}".`);
  }
}

function validateIPv4Layer(raw: Record<string, unknown>, ctx: string): Result<IPv4Layer> {
  const hasIhl = Object.prototype.hasOwnProperty.call(raw, 'ihl');
  const hasOptions = Object.prototype.hasOwnProperty.call(raw, 'options');
  const expectedKeys = [
    'type',
    ...(hasIhl ? ['ihl'] : []),
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
    ...(hasOptions ? ['options'] : []),
  ];
  const checked = validateExactKeys(raw, expectedKeys, ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  let ihl: AutoOrManual<number> = { mode: 'auto' };
  if (hasIhl) {
    const ihlRes = validateAutoOrManualNumber(obj.ihl, `${ctx}.ihl`);
    if (!ihlRes.ok) return ihlRes;
    ihl = ihlRes.value;
  }
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

  let options: IPv4Option[] = [];
  if (hasOptions) {
    const rawOptions = obj.options;
    if (!Array.isArray(rawOptions)) {
      return err(`${ctx}.options must be an array.`);
    }
    if (rawOptions.length > MAX_PERMALINK_OPTIONS) {
      return err(
        `${ctx}.options exceeds maximum of ${MAX_PERMALINK_OPTIONS} options (got ${rawOptions.length}).`,
      );
    }
    options = [];
    for (let i = 0; i < rawOptions.length; i++) {
      const opt = validateIPv4Option(rawOptions[i], `${ctx}.options[${i}]`);
      if (!opt.ok) return opt;
      options.push(opt.value);
    }
  }

  return ok({
    type: 'ipv4',
    ihl,
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
    options,
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

const MAX_PERMALINK_OPTIONS = 64;
const MAX_PERMALINK_OPTION_ITEMS = 64;

function validateRawOptionLength(raw: unknown, context: string): Result<RawOptionLength> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  if (raw.mode === 'none') {
    const checked = validateExactKeys(raw, ['mode'], context);
    if (!checked.ok) return checked;
    return ok({ mode: 'none' });
  }
  return validateAutoOrManualNumber(raw, context);
}

function validateTCPSackBlock(raw: unknown, context: string): Result<TCPSackBlock> {
  const checked = validateExactKeys(raw, ['left', 'right'], context);
  if (!checked.ok) return checked;
  const left = expectNumber(checked.value, 'left', context);
  if (!left.ok) return left;
  const right = expectNumber(checked.value, 'right', context);
  if (!right.ok) return right;
  return ok({ left: left.value, right: right.value });
}

function validateTCPOption(raw: unknown, context: string): Result<TCPOption> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const kind = raw.kind;
  if (typeof kind !== 'string') {
    return err(`${context}.kind must be a string.`);
  }
  switch (kind) {
    case 'eol': {
      const checked = validateExactKeys(raw, ['kind'], context);
      if (!checked.ok) return checked;
      return ok({ kind: 'eol' });
    }
    case 'nop': {
      const checked = validateExactKeys(raw, ['kind'], context);
      if (!checked.ok) return checked;
      return ok({ kind: 'nop' });
    }
    case 'mss': {
      const checked = validateExactKeys(raw, ['kind', 'mss'], context);
      if (!checked.ok) return checked;
      const mss = expectNumber(checked.value, 'mss', context);
      if (!mss.ok) return mss;
      return ok({ kind: 'mss', mss: mss.value });
    }
    case 'windowScale': {
      const checked = validateExactKeys(raw, ['kind', 'shiftCount'], context);
      if (!checked.ok) return checked;
      const shiftCount = expectNumber(checked.value, 'shiftCount', context);
      if (!shiftCount.ok) return shiftCount;
      return ok({ kind: 'windowScale', shiftCount: shiftCount.value });
    }
    case 'sackPermitted': {
      const checked = validateExactKeys(raw, ['kind'], context);
      if (!checked.ok) return checked;
      return ok({ kind: 'sackPermitted' });
    }
    case 'sack': {
      const checked = validateExactKeys(raw, ['kind', 'blocks'], context);
      if (!checked.ok) return checked;
      const rawBlocks = checked.value.blocks;
      if (!Array.isArray(rawBlocks)) {
        return err(`${context}.blocks must be an array.`);
      }
      if (rawBlocks.length > MAX_PERMALINK_OPTION_ITEMS) {
        return err(
          `${context}.blocks exceeds maximum of ${MAX_PERMALINK_OPTION_ITEMS} items (got ${rawBlocks.length}).`,
        );
      }
      const blocks: TCPSackBlock[] = [];
      for (let i = 0; i < rawBlocks.length; i++) {
        const block = validateTCPSackBlock(rawBlocks[i], `${context}.blocks[${i}]`);
        if (!block.ok) return block;
        blocks.push(block.value);
      }
      return ok({ kind: 'sack', blocks });
    }
    case 'timestamps': {
      const checked = validateExactKeys(raw, ['kind', 'tsVal', 'tsEcr'], context);
      if (!checked.ok) return checked;
      const tsVal = expectNumber(checked.value, 'tsVal', context);
      if (!tsVal.ok) return tsVal;
      const tsEcr = expectNumber(checked.value, 'tsEcr', context);
      if (!tsEcr.ok) return tsEcr;
      return ok({ kind: 'timestamps', tsVal: tsVal.value, tsEcr: tsEcr.value });
    }
    case 'raw': {
      const checked = validateExactKeys(raw, ['kind', 'optionKind', 'length', 'dataHex'], context);
      if (!checked.ok) return checked;
      const optionKind = expectNumber(checked.value, 'optionKind', context);
      if (!optionKind.ok) return optionKind;
      const length = validateRawOptionLength(checked.value.length, `${context}.length`);
      if (!length.ok) return length;
      const dataHex = expectString(checked.value, 'dataHex', context);
      if (!dataHex.ok) return dataHex;
      return ok({
        kind: 'raw',
        optionKind: optionKind.value,
        length: length.value,
        dataHex: dataHex.value,
      });
    }
    default:
      return err(`${context} has unknown TCP option kind "${kind}".`);
  }
}

function validateTCPLayer(raw: Record<string, unknown>, ctx: string): Result<TCPLayer> {
  const hasOptions = Object.prototype.hasOwnProperty.call(raw, 'options');
  const expectedKeys = [
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
    ...(hasOptions ? ['options'] : []),
  ];
  const checked = validateExactKeys(raw, expectedKeys, ctx);
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

  let options: TCPOption[] = [];
  if (hasOptions) {
    const rawOptions = obj.options;
    if (!Array.isArray(rawOptions)) {
      return err(`${ctx}.options must be an array.`);
    }
    if (rawOptions.length > MAX_PERMALINK_OPTIONS) {
      return err(
        `${ctx}.options exceeds maximum of ${MAX_PERMALINK_OPTIONS} options (got ${rawOptions.length}).`,
      );
    }
    options = [];
    for (let i = 0; i < rawOptions.length; i++) {
      const opt = validateTCPOption(rawOptions[i], `${ctx}.options[${i}]`);
      if (!opt.ok) return opt;
      options.push(opt.value);
    }
  }

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
    options,
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

function validateGRELayer(raw: unknown, ctx: string): Result<GRELayer> {
  const checked = validateExactKeys(
    raw,
    [
      'type',
      'checksumPresent',
      'keyPresent',
      'sequencePresent',
      'version',
      'protocolType',
      'checksum',
      'key',
      'sequenceNumber',
    ],
    ctx,
  );
  if (!checked.ok) return checked;
  const obj = checked.value;
  const checksumPresent = expectBoolean(obj, 'checksumPresent', ctx);
  if (!checksumPresent.ok) return checksumPresent;
  const keyPresent = expectBoolean(obj, 'keyPresent', ctx);
  if (!keyPresent.ok) return keyPresent;
  const sequencePresent = expectBoolean(obj, 'sequencePresent', ctx);
  if (!sequencePresent.ok) return sequencePresent;
  const version = validateAutoOrManualNumber(obj.version, `${ctx}.version`);
  if (!version.ok) return version;
  const protocolType = validateAutoOrManualNumber(obj.protocolType, `${ctx}.protocolType`);
  if (!protocolType.ok) return protocolType;
  const checksum = validateAutoOrManualNumber(obj.checksum, `${ctx}.checksum`);
  if (!checksum.ok) return checksum;
  const key = expectNumber(obj, 'key', ctx);
  if (!key.ok) return key;
  const sequenceNumber = expectNumber(obj, 'sequenceNumber', ctx);
  if (!sequenceNumber.ok) return sequenceNumber;

  return ok({
    type: 'gre',
    checksumPresent: checksumPresent.value,
    keyPresent: keyPresent.value,
    sequencePresent: sequencePresent.value,
    version: version.value,
    protocolType: protocolType.value,
    checksum: checksum.value,
    key: key.value,
    sequenceNumber: sequenceNumber.value,
  });
}

function validateVXLANLayer(raw: unknown, ctx: string): Result<VXLANLayer> {
  const checked = validateExactKeys(raw, ['type', 'flags', 'vni', 'reserved1', 'reserved2'], ctx);
  if (!checked.ok) return checked;
  const obj = checked.value;
  const flags = validateAutoOrManualNumber(obj.flags, `${ctx}.flags`);
  if (!flags.ok) return flags;
  const vni = expectNumber(obj, 'vni', ctx);
  if (!vni.ok) return vni;
  const reserved1 = expectNumber(obj, 'reserved1', ctx);
  if (!reserved1.ok) return reserved1;
  const reserved2 = expectNumber(obj, 'reserved2', ctx);
  if (!reserved2.ok) return reserved2;

  return ok({
    type: 'vxlan',
    flags: flags.value,
    vni: vni.value,
    reserved1: reserved1.value,
    reserved2: reserved2.value,
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
    case 'vlan':
      return validateVLANLayer(raw, ctx);
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
    case 'gre':
      return validateGRELayer(raw, ctx);
    case 'udp':
      return validateUDPLayer(raw, ctx);
    case 'tcp':
      return validateTCPLayer(raw, ctx);
    case 'vxlan':
      return validateVXLANLayer(raw, ctx);
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
