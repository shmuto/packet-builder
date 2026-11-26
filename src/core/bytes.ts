import { err, ok, type Result } from './result';

const MAC_OCTET_PATTERN = /^[0-9a-fA-F]{2}$/;
const IPV4_OCTET_PATTERN = /^(0|[1-9][0-9]{0,2})$/;
const HEX_ONLY_PATTERN = /^[0-9a-fA-F]*$/;
const HEX_DUMP_BYTES_PER_LINE = 16;

/**
 * Parses a colon-separated MAC address (`aa:bb:cc:dd:ee:ff`, case-insensitive)
 * into a 6-byte Uint8Array.
 */
export function parseMac(text: string): Result<Uint8Array> {
  if (text.length === 0) {
    return err('MAC address is empty. Use the format aa:bb:cc:dd:ee:ff.');
  }

  const parts = text.split(':');
  if (parts.length !== 6) {
    return err(
      `MAC address must have 6 colon-separated bytes (got ${parts.length}).`,
    );
  }

  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) {
    const part = parts[i];
    if (!MAC_OCTET_PATTERN.test(part)) {
      return err(
        `Invalid MAC byte #${i + 1} ("${part}"). Expected 2 hexadecimal digits (00-ff).`,
      );
    }
    bytes[i] = Number.parseInt(part, 16);
  }

  return ok(bytes);
}

/**
 * Parses a dotted-quad IPv4 address (`192.168.0.1`) into a 4-byte Uint8Array.
 * Each octet must be 0-255 with no leading zeros (e.g., `01` is rejected).
 */
export function parseIPv4(text: string): Result<Uint8Array> {
  if (text.length === 0) {
    return err('IPv4 address is empty. Use the format 192.168.0.1.');
  }

  const parts = text.split('.');
  if (parts.length !== 4) {
    return err(
      `IPv4 address must have 4 dot-separated octets (got ${parts.length}).`,
    );
  }

  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!IPV4_OCTET_PATTERN.test(part)) {
      return err(
        `Invalid IPv4 octet #${i + 1} ("${part}"). Expected 0-255 without leading zeros.`,
      );
    }
    const value = Number.parseInt(part, 10);
    if (value > 255) {
      return err(
        `IPv4 octet #${i + 1} ("${part}") is out of range (0-255).`,
      );
    }
    bytes[i] = value;
  }

  return ok(bytes);
}

const IPV6_GROUP_PATTERN = /^[0-9a-fA-F]{1,4}$/;

function parseIPv6Half(half: string, allowEmbeddedIPv4: boolean): Result<number[]> {
  if (half.length === 0) {
    return ok([]);
  }
  const parts = half.split(':');
  const groups: number[] = [];

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part.length === 0) {
      return err('Invalid IPv6 address: unexpected empty group or stray ":".');
    }
    if (part.includes('.')) {
      if (!allowEmbeddedIPv4 || i !== parts.length - 1) {
        return err('Embedded IPv4 address is only allowed as the final segment of an IPv6 address.');
      }
      const embedded = parseIPv4(part);
      if (!embedded.ok) {
        return err(`Invalid embedded IPv4 address in IPv6 ("${part}"): ${embedded.error}`);
      }
      groups.push((embedded.value[0] << 8) | embedded.value[1]);
      groups.push((embedded.value[2] << 8) | embedded.value[3]);
    } else {
      if (!IPV6_GROUP_PATTERN.test(part)) {
        return err(
          `Invalid IPv6 group ("${part}"). Expected 1 to 4 hexadecimal digits (0-ffff).`,
        );
      }
      groups.push(Number.parseInt(part, 16));
    }
  }

  return ok(groups);
}

/**
 * Parses an IPv6 address string (RFC 4291 §2.2: full form, `::` zero compression,
 * and trailing embedded dotted-quad IPv4 such as `::ffff:192.0.2.1`) into a 16-byte Uint8Array.
 * Rejects zone IDs (`%eth0`), multiple `::`, groups longer than 4 hex digits, and wrong group counts.
 */
export function parseIPv6(text: string): Result<Uint8Array> {
  if (text.length === 0) {
    return err('IPv6 address is empty. Use a format such as 2001:db8::1.');
  }
  if (text.includes('%')) {
    return err('IPv6 zone IDs (e.g., %eth0) are not allowed in packet headers.');
  }
  if (/\s/.test(text)) {
    return err('IPv6 address must not contain whitespace.');
  }

  const halves = text.split('::');
  if (halves.length > 2) {
    return err('IPv6 address can contain at most one "::" zero compression.');
  }

  let groups: number[];
  if (halves.length === 1) {
    const parsed = parseIPv6Half(halves[0], true);
    if (!parsed.ok) return parsed;
    if (parsed.value.length !== 8) {
      return err(
        `IPv6 address without "::" must have 8 16-bit groups (got ${parsed.value.length}).`,
      );
    }
    groups = parsed.value;
  } else {
    const left = parseIPv6Half(halves[0], false);
    if (!left.ok) return left;
    const right = parseIPv6Half(halves[1], true);
    if (!right.ok) return right;

    const missing = 8 - (left.value.length + right.value.length);
    if (missing < 1) {
      return err(
        `IPv6 address with "::" has too many groups (${left.value.length + right.value.length} explicit groups; "::" must replace at least 1 zero group).`,
      );
    }
    groups = [...left.value, ...new Array<number>(missing).fill(0), ...right.value];
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return ok(bytes);
}

/**
 * Parses a hexadecimal string (whitespace allowed as separators) into a byte array.
 * Empty or whitespace-only input returns an empty Uint8Array.
 */
export function parseHexBytes(text: string): Result<Uint8Array> {
  const compact = text.replace(/\s+/g, '');
  if (compact.length === 0) {
    return ok(new Uint8Array(0));
  }

  if (!HEX_ONLY_PATTERN.test(compact)) {
    return err('Only hexadecimal characters (0-9, a-f, A-F) and whitespace are allowed.');
  }

  if (compact.length % 2 !== 0) {
    return err(
      `Hex input has an odd number of digits (${compact.length}). Provide 2 hex digits per byte.`,
    );
  }

  const bytes = new Uint8Array(compact.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  }

  return ok(bytes);
}

// Matches `0000: <hex bytes>` emitted by toHexDump
const COLON_DUMP_LINE_PATTERN = /^\s*([0-9a-fA-F]{4,}):\s*(.*)$/;
// Matches Wireshark "Copy as Hex Dump": `<offset>  <1..16 hex bytes>[   <ASCII>]`
const WIRESHARK_DUMP_LINE_PATTERN =
  /^\s*([0-9a-fA-F]{4,})\s{2,}([0-9a-fA-F]{2}(?:\s{1,2}[0-9a-fA-F]{2}){0,15})(?:(\s{3,}.*)|\s*)$/;

function tryStripHexDumpLines(text: string): string | null {
  const nonEmptyLines = text
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);

  if (nonEmptyLines.length === 0) {
    return null;
  }

  // 1) Colon-prefixed hex dump (`0000: 00 11 ...`, emitted by toHexDump):
  //    every line must start with a 4+ hex digit offset followed by a colon.
  const colonMatches = nonEmptyLines.map((line) => COLON_DUMP_LINE_PATTERN.exec(line));
  if (colonMatches.every((m) => m !== null)) {
    return colonMatches.map((m) => m![2]).join(' ');
  }

  // 2) Wireshark "Copy as Hex Dump" (`0000   00 11 ...   ASCII`):
  //    require every line to match, start at offset 0, advance offsets monotonically by byte count,
  //    and either span multiple lines or include the 3+ space ASCII column so plain spaced hex streams
  //    like "deadbeef  cafe" or "0000  00 11" are never misclassified as dumps.
  const wsMatches = nonEmptyLines.map((line) => WIRESHARK_DUMP_LINE_PATTERN.exec(line));
  if (wsMatches.every((m) => m !== null)) {
    let expectedOffset = 0;
    let hasAsciiColumn = false;
    const hexParts: string[] = [];

    for (const match of wsMatches) {
      const offsetValue = Number.parseInt(match![1], 16);
      if (offsetValue !== expectedOffset) {
        return null;
      }
      const hexPart = match![2];
      const byteCount = hexPart.trim().split(/\s+/).length;
      expectedOffset += byteCount;
      if (match![3] !== undefined) {
        hasAsciiColumn = true;
      }
      hexParts.push(hexPart);
    }

    if (wsMatches.length > 1 || hasAsciiColumn) {
      return hexParts.join(' ');
    }
  }

  return null;
}

/**
 * Parses raw hex streams (continuous or whitespace-separated), `toHexDump` output
 * (`0000: 00 11 ...`), or Wireshark "Copy as Hex Dump" output (`0000   00 11 ...   ASCII`).
 */
export function parseHexOrDump(text: string): Result<Uint8Array> {
  const stripped = tryStripHexDumpLines(text);
  return parseHexBytes(stripped ?? text);
}

/** Encodes a UTF-8 string into bytes. */
export function encodeUtf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Strictly decodes bytes as UTF-8 while preserving any leading UTF-8 BOM
 * (`ignoreBOM: true`) so Hex <-> Text round-trips never drop bytes silently.
 */
export function decodeUtf8Strict(bytes: Uint8Array): Result<string> {
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    return ok(text);
  } catch {
    return err('Bytes are not valid UTF-8 and cannot be represented as text.');
  }
}

/** Concatenates multiple byte arrays in order. */
export function concatBytes(...arrays: readonly Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/** Writes an unsigned 16-bit integer in network byte order (big-endian). */
export function writeUint16BE(target: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(offset) || offset < 0 || offset + 2 > target.length) {
    throw new RangeError(`Write offset out of range (offset=${offset}, length=${target.length}).`);
  }
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`Value out of uint16 range (value=${value}). Expected 0-65535.`);
  }
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

/** Writes an unsigned 32-bit integer in network byte order (big-endian). */
export function writeUint32BE(target: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(offset) || offset < 0 || offset + 4 > target.length) {
    throw new RangeError(`Write offset out of range (offset=${offset}, length=${target.length}).`);
  }
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`Value out of uint32 range (value=${value}). Expected 0-4294967295.`);
  }
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

/** Reads an unsigned 16-bit integer in network byte order (big-endian). */
export function readUint16BE(source: Uint8Array, offset: number): number {
  if (!Number.isInteger(offset) || offset < 0 || offset + 2 > source.length) {
    throw new RangeError(`Read offset out of range (offset=${offset}, length=${source.length}).`);
  }
  return (source[offset] << 8) | source[offset + 1];
}

/** Reads an unsigned 32-bit integer in network byte order (big-endian). */
export function readUint32BE(source: Uint8Array, offset: number): number {
  if (!Number.isInteger(offset) || offset < 0 || offset + 4 > source.length) {
    throw new RangeError(`Read offset out of range (offset=${offset}, length=${source.length}).`);
  }
  return (
    ((source[offset] << 24) |
      (source[offset + 1] << 16) |
      (source[offset + 2] << 8) |
      source[offset + 3]) >>>
    0
  );
}

/** Formats a 6-byte Uint8Array as a colon-separated lowercase MAC address. */
export function formatMac(bytes: Uint8Array): string {
  if (bytes.length !== 6) {
    throw new RangeError(`MAC address must be 6 bytes (got ${bytes.length}).`);
  }
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

/** Formats a 4-byte Uint8Array as a dotted-quad IPv4 address. */
export function formatIPv4(bytes: Uint8Array): string {
  if (bytes.length !== 4) {
    throw new RangeError(`IPv4 address must be 4 bytes (got ${bytes.length}).`);
  }
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

/**
 * Formats a 16-byte Uint8Array in RFC 5952 §4 canonical IPv6 form:
 * lowercase hex without leading zeros, compressing the longest run of >= 2 zero groups
 * (first run on a tie), never compressing a single zero group, and rendering IPv4-mapped
 * addresses (`::ffff:0:0/96`) in dotted-quad form per RFC 5952 §5.
 */
export function formatIPv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new RangeError(`IPv6 address must be 16 bytes (got ${bytes.length}).`);
  }

  const groups: number[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push((bytes[i * 2] << 8) | bytes[i * 2 + 1]);
  }

  // RFC 5952 §5: IPv4-mapped IPv6 address (::ffff:a.b.c.d)
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }

  // RFC 5952 §4.2: find longest consecutive run of zero groups of length >= 2 (first wins ties)
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;

  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (runStart === -1) {
        runStart = i;
      }
    } else if (runStart !== -1) {
      const runLen = i - runStart;
      if (runLen >= 2 && runLen > bestLen) {
        bestStart = runStart;
        bestLen = runLen;
      }
      runStart = -1;
    }
  }

  if (bestStart === -1) {
    return groups.map((g) => g.toString(16)).join(':');
  }

  const left = groups
    .slice(0, bestStart)
    .map((g) => g.toString(16))
    .join(':');
  const right = groups
    .slice(bestStart + bestLen)
    .map((g) => g.toString(16))
    .join(':');
  return `${left}::${right}`;
}

/** Formats bytes as a continuous lowercase hexadecimal string without spaces. */
export function toHexString(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Formats bytes as a 16-bytes-per-line hexadecimal dump with hexadecimal offsets.
 * Offset width is at least 4 digits and expands uniformly for inputs >= 65537 bytes
 * (last row offset >= 0x10000). Returns an empty string for empty input.
 */
export function toHexDump(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return '';
  }

  const lastOffset =
    Math.floor((bytes.length - 1) / HEX_DUMP_BYTES_PER_LINE) * HEX_DUMP_BYTES_PER_LINE;
  const offsetWidth = Math.max(4, lastOffset.toString(16).length);

  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += HEX_DUMP_BYTES_PER_LINE) {
    const end = Math.min(offset + HEX_DUMP_BYTES_PER_LINE, bytes.length);
    const hexBytes: string[] = [];
    for (let i = offset; i < end; i++) {
      hexBytes.push(bytes[i].toString(16).padStart(2, '0'));
    }
    const offsetLabel = offset.toString(16).padStart(offsetWidth, '0');
    lines.push(`${offsetLabel}: ${hexBytes.join(' ')}`);
  }

  return lines.join('\n');
}
