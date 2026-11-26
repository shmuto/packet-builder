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
import type { TCPFlags, TCPLayer, TCPOption, TCPSackBlock } from '../types';

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

export function validateTCPPermalink(
  raw: Record<string, unknown>,
  ctx: string,
): Result<TCPLayer> {
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
