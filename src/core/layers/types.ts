/**
 * Represents a header field that is either automatically computed or manually overridden.
 */
export type AutoOrManual<T> =
  | { readonly mode: 'auto' }
  | { readonly mode: 'manual'; readonly value: T };

export function autoValue<T = number>(): AutoOrManual<T> {
  return { mode: 'auto' };
}

export function manualValue<T>(value: T): AutoOrManual<T> {
  return { mode: 'manual', value };
}

export type LayerType = 'ethernet' | 'ipv4' | 'ipv6' | 'tcp';

export interface EthernetLayer {
  readonly type: 'ethernet';
  readonly dstMac: string;
  readonly srcMac: string;
  /** EtherType (16-bit; auto = 0x0800 IPv4, 0x86dd IPv6) */
  readonly etherType: AutoOrManual<number>;
}

/**
 * Length encoding mode for Raw TCP options:
 * - `auto`: length byte computed automatically from 2 + data bytes (TLV)
 * - `manual`: explicit length byte override (TLV; < 2 is an error)
 * - `none`: omit the length byte and emit [kind, ...data] verbatim
 */
export type RawOptionLength = AutoOrManual<number> | { readonly mode: 'none' };

export interface IPv4Flags {
  /** Reserved bit (0 per RFC 791) */
  readonly reserved: boolean;
  /** Don't Fragment */
  readonly df: boolean;
  /** More Fragments */
  readonly mf: boolean;
}

export interface IPv4Layer {
  readonly type: 'ipv4';
  /** Internet Header Length (4-bit, auto = 5 for 20-byte header) */
  readonly ihl: AutoOrManual<number>;
  /** Type of Service / DSCP+ECN (8-bit, 0-255) */
  readonly tos: number;
  /** Total Length (16-bit, auto = 20 + upper bytes length) */
  readonly totalLength: AutoOrManual<number>;
  /** Identification (16-bit, 0-65535) */
  readonly identification: number;
  readonly flags: IPv4Flags;
  /** Fragment Offset (13-bit, 0-8191) */
  readonly fragmentOffset: number;
  /** Time to Live (8-bit, 0-255) */
  readonly ttl: number;
  /** Protocol (8-bit, auto = TCP 6 / IPv4 4 / IPv6 41) */
  readonly protocol: AutoOrManual<number>;
  /** Header Checksum (16-bit, auto = RFC 1071 checksum) */
  readonly headerChecksum: AutoOrManual<number>;
  readonly srcIp: string;
  readonly dstIp: string;
}

export interface IPv6Layer {
  readonly type: 'ipv6';
  /** Traffic Class (8-bit, RFC 8200 §3) */
  readonly trafficClass: number;
  /** Flow Label (20-bit, RFC 8200 §3) */
  readonly flowLabel: number;
  /** Payload Length (16-bit, auto = upper-layer byte length, RFC 8200 §3) */
  readonly payloadLength: AutoOrManual<number>;
  /** Next Header (8-bit, auto = TCP 6 / IPv4 4 / IPv6 41) */
  readonly nextHeader: AutoOrManual<number>;
  /** Hop Limit (8-bit, 0-255, RFC 8200 §3) */
  readonly hopLimit: number;
  readonly srcIp: string;
  readonly dstIp: string;
}

export interface TCPFlags {
  readonly cwr: boolean;
  readonly ece: boolean;
  readonly urg: boolean;
  readonly ack: boolean;
  readonly psh: boolean;
  readonly rst: boolean;
  readonly syn: boolean;
  readonly fin: boolean;
}

export interface TCPSackBlock {
  readonly left: number;
  readonly right: number;
}

export type TCPOption =
  | { readonly kind: 'eol' }
  | { readonly kind: 'nop' }
  | { readonly kind: 'mss'; readonly mss: number }
  | { readonly kind: 'windowScale'; readonly shiftCount: number }
  | { readonly kind: 'sackPermitted' }
  | { readonly kind: 'sack'; readonly blocks: readonly TCPSackBlock[] }
  | { readonly kind: 'timestamps'; readonly tsVal: number; readonly tsEcr: number }
  | {
      readonly kind: 'raw';
      readonly optionKind: number;
      readonly length: RawOptionLength;
      readonly dataHex: string;
    };

export interface TCPLayer {
  readonly type: 'tcp';
  readonly srcPort: number;
  readonly dstPort: number;
  readonly seqNumber: number;
  readonly ackNumber: number;
  readonly dataOffset: AutoOrManual<number>;
  readonly flags: TCPFlags;
  readonly windowSize: number;
  readonly checksum: AutoOrManual<number>;
  readonly urgentPointer: number;
  readonly options: readonly TCPOption[];
}

export type IPPseudoContext =
  | { readonly status: 'valid'; readonly version: 4; readonly srcIp: Uint8Array; readonly dstIp: Uint8Array }
  | { readonly status: 'valid'; readonly version: 6; readonly srcIp: Uint8Array; readonly dstIp: Uint8Array }
  | { readonly status: 'invalid'; readonly version: 4 | 6 }
  | { readonly status: 'absent' };

export type Layer = EthernetLayer | IPv4Layer | IPv6Layer | TCPLayer;

export interface RelativeFieldSpan {
  readonly fieldId: string;
  readonly label: string;
  readonly bitOffset: number;
  readonly bitLength: number;
}

export interface PacketError {
  readonly layerIndex: number | null;
  readonly fieldId?: string;
  readonly message: string;
}

export interface PacketWarning {
  readonly layerIndex: number | null;
  readonly fieldId?: string;
  readonly message: string;
}

export interface LayerEncodeSuccess {
  readonly ok: true;
  readonly bytes: Uint8Array;
  readonly spans: readonly RelativeFieldSpan[];
  readonly warnings: readonly PacketWarning[];
  readonly resolvedAutoValues: Readonly<Record<string, number>>;
}

export interface LayerEncodeFailure {
  readonly ok: false;
  readonly errors: readonly PacketError[];
  readonly warnings: readonly PacketWarning[];
}

export type LayerEncodeResult = LayerEncodeSuccess | LayerEncodeFailure;

export function validateUintRange(
  value: number,
  max: number,
  fieldLabel: string,
): string | null {
  if (Number.isNaN(value)) {
    return `${fieldLabel} must be an integer between 0 and ${max}.`;
  }
  if (!Number.isInteger(value) || value < 0 || value > max) {
    return `${fieldLabel} must be an integer between 0 and ${max} (got ${value}).`;
  }
  return null;
}
