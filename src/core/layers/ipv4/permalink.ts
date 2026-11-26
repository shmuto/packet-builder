import { err, ok, type Result } from '../../result';
import {
  expectBoolean,
  expectNumber,
  expectString,
  isPlainObject,
  MAX_PERMALINK_OPTION_ITEMS,
  MAX_PERMALINK_OPTIONS,
  validateAutoOrManualNumber,
  validateExactKeys,
  validateRawOptionLength,
} from '../permalinkHelpers';
import type { AutoOrManual, IPv4Flags, IPv4Layer, IPv4Option } from '../types';

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

export function validateIPv4Permalink(
  raw: Record<string, unknown>,
  ctx: string,
): Result<IPv4Layer> {
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
