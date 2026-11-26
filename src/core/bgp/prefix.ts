import {
  formatIPv4,
  formatIPv6,
  parseIPv4,
  parseIPv6,
  readUint32BE,
  toHexString,
  writeUint32BE,
} from '../bytes';
import { err, ok, type Result } from '../result';
import { BGP_AFI, type BgpPrefix, type DissectionNode } from './types';

export interface ParsedCidr {
  readonly afi: typeof BGP_AFI.IPV4 | typeof BGP_AFI.IPV6;
  readonly addressBytes: Uint8Array;
  readonly prefixLength: number;
  readonly encodedOctets: Uint8Array;
  readonly canonical: string;
  readonly hadNonZeroHostBits: boolean;
}

export function prefixOctetCount(prefixLength: number): number {
  return Math.ceil(prefixLength / 8);
}

export function parseCidrPrefix(
  cidr: string,
  afi: typeof BGP_AFI.IPV4 | typeof BGP_AFI.IPV6,
): Result<ParsedCidr> {
  const slashIdx = cidr.indexOf('/');
  if (slashIdx === -1 || cidr.indexOf('/', slashIdx + 1) !== -1) {
    return err(`Invalid CIDR prefix "${cidr}". Expected address/length (e.g., 203.0.113.0/24).`);
  }

  const addrPart = cidr.slice(0, slashIdx);
  const lenPart = cidr.slice(slashIdx + 1);
  if (!/^(0|[1-9][0-9]*)$/.test(lenPart)) {
    return err(`Invalid prefix length "${lenPart}" in "${cidr}".`);
  }

  const maxBits = afi === BGP_AFI.IPV4 ? 32 : 128;
  const prefixLength = Number.parseInt(lenPart, 10);
  if (prefixLength < 0 || prefixLength > maxBits) {
    return err(`Prefix length /${prefixLength} out of range for ${afi === BGP_AFI.IPV4 ? 'IPv4' : 'IPv6'} (0-${maxBits}).`);
  }

  const addrResult = afi === BGP_AFI.IPV4 ? parseIPv4(addrPart) : parseIPv6(addrPart);
  if (!addrResult.ok) {
    return err(`Invalid address in prefix "${cidr}": ${addrResult.error}`);
  }

  const fullLen = afi === BGP_AFI.IPV4 ? 4 : 16;
  const masked = new Uint8Array(fullLen);
  const octets = prefixOctetCount(prefixLength);
  for (let i = 0; i < octets; i++) {
    masked[i] = addrResult.value[i];
  }
  let hadNonZeroHostBits = false;
  const remBits = prefixLength % 8;
  if (remBits !== 0 && octets > 0) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    if ((masked[octets - 1] & ~mask) !== 0) {
      hadNonZeroHostBits = true;
    }
    masked[octets - 1] &= mask;
  }
  for (let i = octets; i < fullLen; i++) {
    if (addrResult.value[i] !== 0) {
      hadNonZeroHostBits = true;
      break;
    }
  }

  const canonicalAddr = afi === BGP_AFI.IPV4 ? formatIPv4(masked) : formatIPv6(masked);
  return ok({
    afi,
    addressBytes: masked,
    prefixLength,
    encodedOctets: masked.slice(0, octets),
    canonical: `${canonicalAddr}/${prefixLength}`,
    hadNonZeroHostBits,
  });
}

export interface EncodedPrefixList {
  readonly bytes: Uint8Array;
  readonly nodes: readonly DissectionNode[];
  readonly warnings: readonly string[];
}

export function encodePrefixList(
  prefixes: readonly BgpPrefix[],
  afi: typeof BGP_AFI.IPV4 | typeof BGP_AFI.IPV6,
  addPath: boolean,
  baseOffset: number,
  idPrefix: string,
  roleDescription: string,
): Result<EncodedPrefixList> {
  const chunks: Uint8Array[] = [];
  const nodes: DissectionNode[] = [];
  const warnings: string[] = [];
  let cursor = baseOffset;

  for (let i = 0; i < prefixes.length; i++) {
    const entry = prefixes[i];
    const parsed = parseCidrPrefix(entry.prefix, afi);
    if (!parsed.ok) {
      return err(`Prefix #${i + 1}: ${parsed.error}`);
    }

    const { prefixLength, encodedOctets, canonical, hadNonZeroHostBits } = parsed.value;
    if (hadNonZeroHostBits) {
      warnings.push(
        `Prefix "${entry.prefix}" has non-zero host bits after /${prefixLength}; masked to ${canonical} per RFC 4271 §4.3.`,
      );
    }
    const pathId = entry.pathId ?? 0;
    if (addPath && (!Number.isInteger(pathId) || pathId < 0 || pathId > 0xffffffff)) {
      return err(`Prefix #${i + 1}: ADD-PATH Path Identifier must be a 32-bit unsigned integer (got ${pathId}).`);
    }

    const itemLen = (addPath ? 4 : 0) + 1 + encodedOctets.length;
    const buf = new Uint8Array(itemLen);
    const children: DissectionNode[] = [];
    let pos = 0;

    if (addPath) {
      writeUint32BE(buf, pos, pathId);
      children.push({
        id: `${idPrefix}[${i}].pathId`,
        label: 'Path Identifier',
        value: String(pathId),
        explanation:
          '32-bit ADD-PATH identifier distinguishing multiple advertised paths for the same prefix.',
        reference: 'RFC 7911 §3',
        byteRange: { start: cursor + pos, end: cursor + pos + 4 },
      });
      pos += 4;
    }

    buf[pos] = prefixLength;
    children.push({
      id: `${idPrefix}[${i}].length`,
      label: 'Prefix Length',
      value: `${prefixLength} bits (${encodedOctets.length} ${encodedOctets.length === 1 ? 'octet' : 'octets'})`,
      explanation:
        'Length of the prefix in bits; BGP encodes only ceil(length / 8) octets to save wire space.',
      reference: 'RFC 4271 §4.3',
      byteRange: { start: cursor + pos, end: cursor + pos + 1 },
    });
    pos += 1;

    if (encodedOctets.length > 0) {
      buf.set(encodedOctets, pos);
      children.push({
        id: `${idPrefix}[${i}].prefix`,
        label: 'Prefix',
        value: `${canonical} (0x${toHexString(encodedOctets)})`,
        explanation: `${roleDescription} ${canonical}, encoded using the minimum ${encodedOctets.length} significant ${encodedOctets.length === 1 ? 'octet' : 'octets'}.`,
        reference: afi === BGP_AFI.IPV4 ? 'RFC 4271 §4.3' : 'RFC 4760 §3',
        byteRange: { start: cursor + pos, end: cursor + pos + encodedOctets.length },
      });
      pos += encodedOctets.length;
    }

    const displayValue = addPath ? `${canonical} (Path ID ${pathId})` : canonical;
    nodes.push({
      id: `${idPrefix}[${i}]`,
      label: `Prefix ${canonical}`,
      value: displayValue,
      explanation: `${roleDescription} ${canonical}${addPath ? ` with ADD-PATH Path Identifier ${pathId}` : ''}.`,
      reference: addPath
        ? 'RFC 7911 §3'
        : afi === BGP_AFI.IPV4
          ? 'RFC 4271 §4.3'
          : 'RFC 4760 §3',
      byteRange: { start: cursor, end: cursor + itemLen },
      children,
    });

    chunks.push(buf);
    cursor += itemLen;
  }

  const totalLen = cursor - baseOffset;
  const out = new Uint8Array(totalLen);
  let writePos = 0;
  for (const chunk of chunks) {
    out.set(chunk, writePos);
    writePos += chunk.length;
  }
  return ok({ bytes: out, nodes, warnings });
}

export interface DecodedPrefixList {
  readonly prefixes: readonly BgpPrefix[];
  readonly nodes: readonly DissectionNode[];
  readonly notes: readonly string[];
}

export function decodePrefixList(
  bytes: Uint8Array,
  start: number,
  end: number,
  afi: typeof BGP_AFI.IPV4 | typeof BGP_AFI.IPV6,
  addPath: boolean,
  idPrefix: string,
  roleDescription: string,
): DecodedPrefixList {
  const prefixes: BgpPrefix[] = [];
  const nodes: DissectionNode[] = [];
  const notes: string[] = [];
  const maxBits = afi === BGP_AFI.IPV4 ? 32 : 128;
  const fullLen = afi === BGP_AFI.IPV4 ? 4 : 16;

  let cursor = start;
  let index = 0;

  while (cursor < end) {
    const itemStart = cursor;
    const children: DissectionNode[] = [];
    let pathId: number | undefined;

    if (addPath) {
      if (cursor + 4 > end) {
        notes.push(
          `Truncated ADD-PATH Path Identifier at byte ${cursor} (${end - cursor} bytes remaining).`,
        );
        nodes.push({
          id: `${idPrefix}[${index}].truncated`,
          label: 'Truncated Prefix Data',
          value: `0x${toHexString(bytes.slice(cursor, end))}`,
          explanation: 'Remaining bytes were too short to hold a 4-byte ADD-PATH Path Identifier.',
          reference: 'RFC 7911 §3',
          byteRange: { start: cursor, end },
        });
        break;
      }
      pathId = readUint32BE(bytes, cursor);
      children.push({
        id: `${idPrefix}[${index}].pathId`,
        label: 'Path Identifier',
        value: String(pathId),
        explanation:
          '32-bit ADD-PATH identifier distinguishing multiple advertised paths for the same prefix.',
        reference: 'RFC 7911 §3',
        byteRange: { start: cursor, end: cursor + 4 },
      });
      cursor += 4;
    }

    if (cursor >= end) {
      notes.push(`Truncated prefix length after ADD-PATH Path Identifier at byte ${cursor}.`);
      nodes.push({
        id: `${idPrefix}[${index}].truncated`,
        label: 'Truncated Prefix Entry',
        value: `Path ID ${pathId}`,
        explanation: 'ADD-PATH Path Identifier was not followed by a prefix length byte.',
        reference: 'RFC 7911 §3',
        byteRange: { start: itemStart, end },
        children,
      });
      break;
    }

    const prefixLen = bytes[cursor];
    const lenOffset = cursor;
    cursor += 1;
    const octets = prefixOctetCount(prefixLen);

    if (prefixLen > maxBits || cursor + octets > end) {
      const reason =
        prefixLen > maxBits
          ? `Prefix length /${prefixLen} exceeds maximum /${maxBits}.`
          : `Prefix /${prefixLen} requires ${octets} octets, but only ${end - cursor} remain.`;
      notes.push(`Malformed prefix at byte ${itemStart}: ${reason}`);
      children.push({
        id: `${idPrefix}[${index}].malformed`,
        label: 'Malformed Prefix',
        value: `/${prefixLen} (0x${toHexString(bytes.slice(lenOffset, end))})`,
        explanation: reason,
        reference: afi === BGP_AFI.IPV4 ? 'RFC 4271 §6.3' : 'RFC 4760 §7',
        byteRange: { start: lenOffset, end },
      });
      nodes.push({
        id: `${idPrefix}[${index}]`,
        label: 'Malformed Prefix Entry',
        value: `/${prefixLen}`,
        explanation: reason,
        reference: afi === BGP_AFI.IPV4 ? 'RFC 4271 §6.3' : 'RFC 4760 §7',
        byteRange: { start: itemStart, end },
        children,
      });
      break;
    }

    children.push({
      id: `${idPrefix}[${index}].length`,
      label: 'Prefix Length',
      value: `${prefixLen} bits (${octets} ${octets === 1 ? 'octet' : 'octets'})`,
      explanation:
        'Length of the prefix in bits; BGP encodes only ceil(length / 8) octets to save wire space.',
      reference: 'RFC 4271 §4.3',
      byteRange: { start: lenOffset, end: lenOffset + 1 },
    });

    const fullAddr = new Uint8Array(fullLen);
    for (let j = 0; j < octets; j++) {
      fullAddr[j] = bytes[cursor + j];
    }
    const remBits = prefixLen % 8;
    if (remBits !== 0 && octets > 0) {
      const mask = (0xff << (8 - remBits)) & 0xff;
      if ((fullAddr[octets - 1] & ~mask) !== 0) {
        notes.push(
          `Prefix at byte ${itemStart} has non-zero trailing host bits after /${prefixLen}; masked on decode.`,
        );
        fullAddr[octets - 1] &= mask;
      }
    }

    const addrStr = afi === BGP_AFI.IPV4 ? formatIPv4(fullAddr) : formatIPv6(fullAddr);
    const canonical = `${addrStr}/${prefixLen}`;

    if (octets > 0) {
      children.push({
        id: `${idPrefix}[${index}].prefix`,
        label: 'Prefix',
        value: `${canonical} (0x${toHexString(bytes.slice(cursor, cursor + octets))})`,
        explanation: `${roleDescription} ${canonical}, encoded using the minimum ${octets} significant ${octets === 1 ? 'octet' : 'octets'}.`,
        reference: afi === BGP_AFI.IPV4 ? 'RFC 4271 §4.3' : 'RFC 4760 §3',
        byteRange: { start: cursor, end: cursor + octets },
      });
      cursor += octets;
    }

    const displayValue = addPath ? `${canonical} (Path ID ${pathId})` : canonical;
    nodes.push({
      id: `${idPrefix}[${index}]`,
      label: `Prefix ${canonical}`,
      value: displayValue,
      explanation: `${roleDescription} ${canonical}${addPath ? ` with ADD-PATH Path Identifier ${pathId}` : ''}.`,
      reference: addPath
        ? 'RFC 7911 §3'
        : afi === BGP_AFI.IPV4
          ? 'RFC 4271 §4.3'
          : 'RFC 4760 §3',
      byteRange: { start: itemStart, end: cursor },
      children,
    });

    prefixes.push(addPath ? { prefix: canonical, pathId } : { prefix: canonical });
    index += 1;
  }

  return { prefixes, nodes, notes };
}
