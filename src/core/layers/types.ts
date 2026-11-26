import type { LayerType } from './registry';

export type { LayerType };

export interface FieldDoc {
  /** 1-2 plain-English sentences explaining what the field does and typical values. */
  readonly summary: string;
  /** Specific RFC or IEEE specification section reference (e.g., "RFC 791 §3.1"). */
  readonly reference: string;
}

/**
 * 自動計算または手動上書きを表すフィールド値。
 * 学習用に、自動計算されるヘッダ項目（長さ・チェックサム等）へ任意の値を手動指定できる。
 */
export type AutoOrManual<T> =
  | { readonly mode: 'auto' }
  | { readonly mode: 'manual'; readonly value: T };

/** 自動計算モードの値を生成する */
export function autoValue<T = number>(): AutoOrManual<T> {
  return { mode: 'auto' };
}

/** 手動指定モードの値を生成する */
export function manualValue<T>(value: T): AutoOrManual<T> {
  return { mode: 'manual', value };
}

export interface EthernetLayer {
  readonly type: 'ethernet';
  /** 宛先 MAC アドレス（例: aa:bb:cc:dd:ee:ff） */
  readonly dstMac: string;
  /** 送信元 MAC アドレス（例: 11:22:33:44:55:66） */
  readonly srcMac: string;
  /** EtherType / TPID (16-bit; auto = 0x0800 IPv4, 0x86dd IPv6, 0x0806 ARP, 0x8100 VLAN, 0x88a8 QinQ S-tag) */
  readonly etherType: AutoOrManual<number>;
}

/**
 * IEEE 802.1Q / 802.1ad VLAN tag (4 bytes following the TPID in the preceding Ethernet or outer VLAN header).
 * Encodes TCI (PCP 3b + DEI 1b + VID 12b) + next EtherType / inner TPID (16b).
 */
export interface VLANLayer {
  readonly type: 'vlan';
  /** Priority Code Point (3-bit, 0-7, IEEE 802.1Q §9.6) */
  readonly pcp: number;
  /** Drop Eligible Indicator (1-bit, IEEE 802.1Q §9.6) */
  readonly dei: boolean;
  /** VLAN Identifier (12-bit, 0-4095; 0 = priority-tagged, 4095 = reserved, IEEE 802.1Q §9.6) */
  readonly vid: number;
  /** Encapsulated EtherType or inner VLAN TPID (16-bit; auto = 0x0800 / 0x0806 / 0x86dd / 0x8100) */
  readonly etherType: AutoOrManual<number>;
}

export interface ARPLayer {
  readonly type: 'arp';
  /** Hardware Type (16 bit, auto = 1 for Ethernet, RFC 826) */
  readonly hardwareType: AutoOrManual<number>;
  /** Protocol Type (16 bit, auto = 0x0800 for IPv4, RFC 826) */
  readonly protocolType: AutoOrManual<number>;
  /** Hardware Address Length (8 bit, auto = 6 for 48-bit MAC) */
  readonly hardwareLength: AutoOrManual<number>;
  /** Protocol Address Length (8 bit, auto = 4 for 32-bit IPv4) */
  readonly protocolLength: AutoOrManual<number>;
  /** Operation (16 bit, 1 = Request, 2 = Reply) */
  readonly operation: number;
  /** Sender Hardware Address (6-byte MAC) */
  readonly senderMac: string;
  /** Sender Protocol Address (4-byte IPv4) */
  readonly senderIp: string;
  /** Target Hardware Address (6-byte MAC; 00:00:00:00:00:00 for requests) */
  readonly targetMac: string;
  /** Target Protocol Address (4-byte IPv4) */
  readonly targetIp: string;
}

/**
 * Length encoding mode for Raw TCP/IPv4 options:
 * - `auto`: length byte computed automatically from 2 + data bytes (TLV)
 * - `manual`: explicit length byte override (TLV; < 2 is an error)
 * - `none`: omit the length byte and emit [type/kind, ...data] verbatim (lossless malformed decode fallback)
 */
export type RawOptionLength = AutoOrManual<number> | { readonly mode: 'none' };

export interface IPv4Flags {
  /** Reserved ビット（RFC 791 では 0 固定） */
  readonly reserved: boolean;
  /** Don't Fragment（フラグメント禁止） */
  readonly df: boolean;
  /** More Fragments（後続フラグメントあり） */
  readonly mf: boolean;
}

export type IPv4Option =
  | { readonly kind: 'eol' }
  | { readonly kind: 'nop' }
  | {
      readonly kind: 'rr';
      /** 8-bit Pointer (auto = 4, RFC 791 §3.1) */
      readonly pointer: AutoOrManual<number>;
      /** Route data IPv4 addresses (n × 4 bytes) */
      readonly addresses: readonly string[];
    }
  | {
      readonly kind: 'timestamp';
      /** 8-bit Pointer (default 5, RFC 791 §3.1) */
      readonly pointer: number;
      /** 4-bit Overflow counter (0-15, RFC 791 §3.1) */
      readonly overflow: number;
      /** 4-bit Flag (0=timestamps only, 1=IP+timestamps, 3=prespecified IPs, RFC 791 §3.1) */
      readonly flag: number;
      /** Timestamp data bytes in hexadecimal */
      readonly dataHex: string;
    }
  | {
      readonly kind: 'lsrr';
      /** 8-bit Pointer (auto = 4, RFC 791 §3.1) */
      readonly pointer: AutoOrManual<number>;
      /** Loose source route IPv4 addresses (n × 4 bytes) */
      readonly addresses: readonly string[];
    }
  | {
      readonly kind: 'ssrr';
      /** 8-bit Pointer (auto = 4, RFC 791 §3.1) */
      readonly pointer: AutoOrManual<number>;
      /** Strict source route IPv4 addresses (n × 4 bytes) */
      readonly addresses: readonly string[];
    }
  | {
      readonly kind: 'routerAlert';
      /** 16-bit Value (0 = "Router shall examine packet", RFC 2113 §2.1) */
      readonly value: number;
    }
  | {
      readonly kind: 'raw';
      /** 8-bit Option Type byte (copied 1b + class 2b + number 5b, RFC 791 §3.1) */
      readonly optionType: number;
      /** 8-bit Option Length (auto = 2 + data bytes, manual, or none for verbatim raw bytes) */
      readonly length: RawOptionLength;
      /** Option data bytes in hexadecimal (without Type/Length bytes) */
      readonly dataHex: string;
    };

export interface IPv4Layer {
  readonly type: 'ipv4';
  /** Internet Header Length (4-bit, in 32-bit words; auto = 5 + ceil(options / 4), RFC 791 §3.1) */
  readonly ihl: AutoOrManual<number>;
  /** Type of Service / DSCP+ECN（8 ビット、0〜255） */
  readonly tos: number;
  /** Total Length（16 ビット、自動時は ヘッダ長 + 上位バイト長） */
  readonly totalLength: AutoOrManual<number>;
  /** Identification（16 ビット、0〜65535） */
  readonly identification: number;
  /** Flags（3 ビット：Reserved / DF / MF） */
  readonly flags: IPv4Flags;
  /** Fragment Offset（13 ビット、0〜8191） */
  readonly fragmentOffset: number;
  /** Time to Live（8 ビット、0〜255） */
  readonly ttl: number;
  /** Protocol（8 ビット、自動時は ICMP=1 / TCP=6 / UDP=17 等） */
  readonly protocol: AutoOrManual<number>;
  /** Header Checksum（16 ビット、自動時は RFC 1071 チェックサム） */
  readonly headerChecksum: AutoOrManual<number>;
  /** 送信元 IPv4 アドレス（例: 192.168.0.1） */
  readonly srcIp: string;
  /** 宛先 IPv4 アドレス（例: 192.168.0.2） */
  readonly dstIp: string;
  /** Ordered list of IPv4 options (padded to 32-bit boundary, max 40 bytes, RFC 791 §3.1) */
  readonly options: readonly IPv4Option[];
}

export interface IPv6Layer {
  readonly type: 'ipv6';
  /** Traffic Class (8-bit: 6-bit DSCP + 2-bit ECN, 0-255, RFC 8200 §3) */
  readonly trafficClass: number;
  /** Flow Label (20-bit, 0-1048575 / 0x00000-0xfffff, RFC 8200 §3) */
  readonly flowLabel: number;
  /** Payload Length (16-bit, auto = upper-layer byte length, max 65535, RFC 8200 §3) */
  readonly payloadLength: AutoOrManual<number>;
  /** Next Header (8-bit IANA protocol number, auto = TCP 6 / UDP 17 / IPv4 4 / IPv6 41) */
  readonly nextHeader: AutoOrManual<number>;
  /** Hop Limit (8-bit, 0-255, RFC 8200 §3) */
  readonly hopLimit: number;
  /** Source IPv6 address (128-bit, RFC 4291 / RFC 5952) */
  readonly srcIp: string;
  /** Destination IPv6 address (128-bit, RFC 4291 / RFC 5952) */
  readonly dstIp: string;
}

export interface ICMPLayer {
  readonly type: 'icmp';
  /** Type（8 ビット、例: Echo Request=8, Echo Reply=0） */
  readonly icmpType: number;
  /** Code（8 ビット、0〜255） */
  readonly code: number;
  /** Checksum（16 ビット、自動時はヘッダ＋ペイロード全体の RFC 1071 チェックサム） */
  readonly checksum: AutoOrManual<number>;
  /** Identifier（16 ビット、0〜65535） */
  readonly identifier: number;
  /** Sequence Number（16 ビット、0〜65535） */
  readonly sequenceNumber: number;
}

export type ICMPv6Rest =
  | {
      readonly kind: 'echo';
      /** 16-bit Identifier (RFC 4443 §4.1 / §4.2) */
      readonly identifier: number;
      /** 16-bit Sequence Number (RFC 4443 §4.1 / §4.2) */
      readonly sequence: number;
    }
  | {
      readonly kind: 'raw';
      /** 32-bit type-specific body header: MTU (Type 2), Pointer (Type 4), or Unused */
      readonly value: number;
    };

export interface ICMPv6Layer {
  readonly type: 'icmpv6';
  /** Message Type (8-bit, e.g., 128=Echo Request, 129=Echo Reply, 2=Packet Too Big, RFC 4443 §2.1) */
  readonly icmpType: number;
  /** Message Code (8-bit, 0-255, RFC 4443 §2.1) */
  readonly code: number;
  /** Checksum (16-bit, auto = mandatory IPv6 pseudo-header + ICMPv6 checksum, RFC 4443 §2.3) */
  readonly checksum: AutoOrManual<number>;
  /** Type-dependent 32-bit header word (Echo Identifier/Sequence or raw 32-bit MTU/Pointer/Unused) */
  readonly rest: ICMPv6Rest;
}

export interface UDPLayer {
  readonly type: 'udp';
  /** 送信元ポート番号（16 ビット、0〜65535） */
  readonly srcPort: number;
  /** 宛先ポート番号（16 ビット、0〜65535） */
  readonly dstPort: number;
  /** Length（16 ビット、自動時は 8 + 上位バイト長） */
  readonly length: AutoOrManual<number>;
  /** Checksum（16 ビット、自動時は IPv4/IPv6 擬似ヘッダ含むチェックサム） */
  readonly checksum: AutoOrManual<number>;
}

export interface TCPFlags {
  /** Congestion Window Reduced (RFC 3168 / RFC 9293) */
  readonly cwr: boolean;
  /** ECN-Echo */
  readonly ece: boolean;
  /** Urgent */
  readonly urg: boolean;
  /** Acknowledgment */
  readonly ack: boolean;
  /** Push */
  readonly psh: boolean;
  /** Reset */
  readonly rst: boolean;
  /** Synchronize */
  readonly syn: boolean;
  /** Finish */
  readonly fin: boolean;
}

export interface TCPSackBlock {
  /** Left Edge of SACK block (32-bit sequence number, RFC 2018 §3) */
  readonly left: number;
  /** Right Edge of SACK block (32-bit sequence number, RFC 2018 §3) */
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
      /** 8-bit Option Kind (0-255, RFC 9293 §3.1) */
      readonly optionKind: number;
      /** 8-bit Option Length (auto = 2 + data bytes, manual, or none for verbatim raw bytes) */
      readonly length: RawOptionLength;
      /** Option data bytes in hexadecimal (without Kind/Length bytes) */
      readonly dataHex: string;
    };

export interface TCPLayer {
  readonly type: 'tcp';
  /** 送信元ポート番号（16 ビット、0〜65535） */
  readonly srcPort: number;
  /** 宛先ポート番号（16 ビット、0〜65535） */
  readonly dstPort: number;
  /** Sequence Number（32 ビット、0〜4294967295） */
  readonly seqNumber: number;
  /** Acknowledgment Number（32 ビット、0〜4294967295） */
  readonly ackNumber: number;
  /** Data Offset（4 ビット、自動時は 5 + ceil(options / 4)） */
  readonly dataOffset: AutoOrManual<number>;
  /** Control Bits（8 ビット、RFC 9293 Section 3.1） */
  readonly flags: TCPFlags;
  /** Window Size（16 ビット、0〜65535） */
  readonly windowSize: number;
  /** Checksum（16 ビット、自動時は IPv4/IPv6 擬似ヘッダ含む RFC 9293 チェックサム） */
  readonly checksum: AutoOrManual<number>;
  /** Urgent Pointer（16 ビット、0〜65535） */
  readonly urgentPointer: number;
  /** Ordered list of TCP options (padded to 32-bit boundary, max 40 bytes, RFC 9293 §3.1) */
  readonly options: readonly TCPOption[];
}

/** BGP-4 message types defined in RFC 4271 Section 4.1 */
export type BGPMessageType = 1 | 2 | 3 | 4;

export interface BGPLayer {
  readonly type: 'bgp';
  /** Message Type: 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE (RFC 4271 §4.1) */
  readonly bgpType: BGPMessageType;
  /** 16-byte Marker (auto = 16 bytes of 0xff per RFC 4271 §4.1; manual = 32 hex digits) */
  readonly marker: AutoOrManual<string>;
  /** Total BGP message length including 19-byte header (16-bit, RFC 4271 §4.1) */
  readonly length: AutoOrManual<number>;
  // OPEN (Type 1, RFC 4271 §4.2)
  /** BGP protocol version (8-bit, auto = 4) */
  readonly version: AutoOrManual<number>;
  /** My Autonomous System (16-bit ASN) */
  readonly myAs: number;
  /** Hold Time in seconds (16-bit; must be 0 or >= 3 per RFC 4271 §4.2) */
  readonly holdTime: number;
  /** BGP Identifier (IPv4 dotted-quad format) */
  readonly bgpIdentifier: string;
  /** Optional Parameters Length (8-bit, auto = payload byte length) */
  readonly optParamLength: AutoOrManual<number>;
  // UPDATE (Type 2, RFC 4271 §4.3)
  /** Withdrawn Routes Length (16-bit, auto = 0) */
  readonly withdrawnRoutesLength: AutoOrManual<number>;
  /** Total Path Attribute Length (16-bit, auto = 0) */
  readonly totalPathAttrLength: AutoOrManual<number>;
  // NOTIFICATION (Type 3, RFC 4271 §4.5)
  /** Error Code (8-bit, 1..6 per RFC 4271 §4.5, 7 per RFC 7313) */
  readonly errorCode: number;
  /** Error Subcode (8-bit) */
  readonly errorSubcode: number;
}

export interface GRELayer {
  readonly type: 'gre';
  /** C bit (bit 0): Checksum Present — appends 16-bit Checksum + 16-bit Reserved1 (RFC 2784 §2.2) */
  readonly checksumPresent: boolean;
  /** K bit (bit 2): Key Present — appends 32-bit Key (RFC 2890 §2.1) */
  readonly keyPresent: boolean;
  /** S bit (bit 3): Sequence Number Present — appends 32-bit Sequence Number (RFC 2890 §2.2) */
  readonly sequencePresent: boolean;
  /** GRE Version (3-bit, 0-7; auto = 0 per RFC 2784 §2.3.1) */
  readonly version: AutoOrManual<number>;
  /** Encapsulated Protocol Type (16-bit EtherType; auto = 0x0800 IPv4 / 0x86dd IPv6 / 0x6558 TEB / 0x0806 ARP / 0x8100 VLAN, RFC 2784 §2.4) */
  readonly protocolType: AutoOrManual<number>;
  /** Optional 16-bit Checksum when C=1 (auto = RFC 1071 over GRE header + payload, RFC 2784 §2.5) */
  readonly checksum: AutoOrManual<number>;
  /** Optional 32-bit Key when K=1 (0-4294967295, RFC 2890 §2.1) */
  readonly key: number;
  /** Optional 32-bit Sequence Number when S=1 (0-4294967295, RFC 2890 §2.2) */
  readonly sequenceNumber: number;
}

export interface VXLANLayer {
  readonly type: 'vxlan';
  /** 8-bit Flags (auto = 0x08 with I-flag set for valid VNI, RFC 7348 §5) */
  readonly flags: AutoOrManual<number>;
  /** 24-bit VXLAN Network Identifier (0-16777215, RFC 7348 §5) */
  readonly vni: number;
  /** 24-bit Reserved field following Flags (0-16777215, default 0, RFC 7348 §5) */
  readonly reserved1: number;
  /** 8-bit Reserved field following VNI (0-255, default 0, RFC 7348 §5) */
  readonly reserved2: number;
}

export type Layer =
  | EthernetLayer
  | VLANLayer
  | ARPLayer
  | IPv4Layer
  | IPv6Layer
  | ICMPLayer
  | ICMPv6Layer
  | GRELayer
  | UDPLayer
  | TCPLayer
  | VXLANLayer
  | BGPLayer;

/** レイヤー内の相対フィールド定義（エンコーダ内部で使用） */
export interface RelativeFieldSpan {
  readonly fieldId: string;
  readonly label: string;
  /** 当該レイヤー先頭からの開始ビット位置（0 始まり） */
  readonly bitOffset: number;
  /** フィールドのビット長（1 以上） */
  readonly bitLength: number;
}

/** パケット全体におけるフィールドとビット範囲の対応 */
export interface FieldSpan {
  readonly section: 'layer' | 'payload';
  /** レイヤー配列のインデックス（payload の場合は layers.length） */
  readonly layerIndex: number;
  readonly layerType: LayerType | 'payload';
  readonly fieldId: string;
  readonly label: string;
  /** パケット先頭からの開始ビット位置（0 始まり） */
  readonly bitOffset: number;
  /** フィールドのビット長（1 以上） */
  readonly bitLength: number;
}

/** エンコードを中止させる入力・構成エラー */
export interface PacketError {
  readonly layerIndex: number | null;
  readonly fieldId?: string;
  readonly message: string;
}

/** エンコードは可能だが学習上注意すべき点を示す警告 */
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

export interface BuildPacketSuccess {
  readonly ok: true;
  readonly bytes: Uint8Array;
  readonly spans: readonly FieldSpan[];
  readonly warnings: readonly PacketWarning[];
  /** 各レイヤーで自動計算された値（UI の「自動」表示向け） */
  readonly resolvedAutoValues: readonly Readonly<Record<string, number>>[];
}

export interface BuildPacketFailure {
  readonly ok: false;
  readonly errors: readonly PacketError[];
  readonly warnings: readonly PacketWarning[];
}

export type BuildPacketResult = BuildPacketSuccess | BuildPacketFailure;

/**
 * 符号なし整数の範囲検証を行い、範囲外または非整数の場合はエラーメッセージを返す。
 */
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
