import { writeUint16BE } from './bytes';
import { err, ok, type Result } from './result';

/**
 * Computes the 16-bit Internet Checksum defined in RFC 1071.
 *
 * - Treats bytes as big-endian 16-bit words.
 * - Pads odd-length input with a trailing 0x00 byte (RFC 1071 Section 4.1).
 * - Returns the one's complement of the one's complement sum (0x0000-0xffff).
 */
export function internetChecksum(bytes: Uint8Array): number {
  let sum = 0;

  for (let i = 0; i < bytes.length; i += 2) {
    const high = bytes[i];
    const low = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const word = (high << 8) | low;
    sum += word;
    // Fold carry into 16 bits on every step to prevent 32-bit overflow on large inputs
    if (sum > 0xffff) {
      sum = (sum & 0xffff) + (sum >>> 16);
    }
  }

  return (~sum) & 0xffff;
}

export interface IPv4PseudoHeaderParams {
  /** Source IPv4 address (4 bytes) */
  readonly srcIp: Uint8Array;
  /** Destination IPv4 address (4 bytes) */
  readonly dstIp: Uint8Array;
  /** IPv4 protocol number (e.g., TCP=6, UDP=17) */
  readonly protocol: number;
  /** Upper-layer header + payload with checksum field zeroed */
  readonly segment: Uint8Array;
}

/**
 * Computes the RFC 1071 checksum prefixed with the 12-byte IPv4 pseudo-header
 * (RFC 768 / RFC 9293 Section 3.1).
 *
 * Note: Returns the raw checksum value; UDP's 0x0000 -> 0xffff mapping (RFC 768)
 * is applied by the UDP encoder because TCP (RFC 9293) keeps 0x0000 as-is.
 */
export function ipv4PseudoHeaderChecksum(params: IPv4PseudoHeaderParams): Result<number> {
  const { srcIp, dstIp, protocol, segment } = params;

  if (srcIp.length !== 4) {
    return err(`Source IPv4 address must be 4 bytes (got ${srcIp.length}).`);
  }
  if (dstIp.length !== 4) {
    return err(`Destination IPv4 address must be 4 bytes (got ${dstIp.length}).`);
  }
  if (!Number.isInteger(protocol) || protocol < 0 || protocol > 0xff) {
    return err(`Protocol number must be an integer between 0 and 255 (got ${protocol}).`);
  }
  if (segment.length > 0xffff) {
    return err(`Upper-layer segment exceeds 65535 bytes (got ${segment.length}).`);
  }

  // IPv4 pseudo-header (12 bytes) + upper-layer segment
  const buffer = new Uint8Array(12 + segment.length);
  buffer.set(srcIp, 0);
  buffer.set(dstIp, 4);
  buffer[8] = 0;
  buffer[9] = protocol;
  writeUint16BE(buffer, 10, segment.length);
  buffer.set(segment, 12);

  return ok(internetChecksum(buffer));
}
