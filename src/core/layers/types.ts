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

export type LayerType = 'ethernet' | 'ipv4' | 'icmp' | 'udp' | 'tcp';

export interface EthernetLayer {
  readonly type: 'ethernet';
  /** 宛先 MAC アドレス（例: aa:bb:cc:dd:ee:ff） */
  readonly dstMac: string;
  /** 送信元 MAC アドレス（例: 11:22:33:44:55:66） */
  readonly srcMac: string;
  /** EtherType（16 ビット、自動時は直上が IPv4 なら 0x0800） */
  readonly etherType: AutoOrManual<number>;
}

export interface IPv4Flags {
  /** Reserved ビット（RFC 791 では 0 固定） */
  readonly reserved: boolean;
  /** Don't Fragment（フラグメント禁止） */
  readonly df: boolean;
  /** More Fragments（後続フラグメントあり） */
  readonly mf: boolean;
}

export interface IPv4Layer {
  readonly type: 'ipv4';
  /** Type of Service / DSCP+ECN（8 ビット、0〜255） */
  readonly tos: number;
  /** Total Length（16 ビット、自動時は 20 + 上位バイト長） */
  readonly totalLength: AutoOrManual<number>;
  /** Identification（16 ビット、0〜65535） */
  readonly identification: number;
  /** Flags（3 ビット：Reserved / DF / MF） */
  readonly flags: IPv4Flags;
  /** Fragment Offset（13 ビット、0〜8191） */
  readonly fragmentOffset: number;
  /** Time to Live（8 ビット、0〜255） */
  readonly ttl: number;
  /** Protocol（8 ビット、自動時は ICMP=1 / TCP=6 / UDP=17） */
  readonly protocol: AutoOrManual<number>;
  /** Header Checksum（16 ビット、自動時は RFC 1071 チェックサム） */
  readonly headerChecksum: AutoOrManual<number>;
  /** 送信元 IPv4 アドレス（例: 192.168.0.1） */
  readonly srcIp: string;
  /** 宛先 IPv4 アドレス（例: 192.168.0.2） */
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

export interface UDPLayer {
  readonly type: 'udp';
  /** 送信元ポート番号（16 ビット、0〜65535） */
  readonly srcPort: number;
  /** 宛先ポート番号（16 ビット、0〜65535） */
  readonly dstPort: number;
  /** Length（16 ビット、自動時は 8 + 上位バイト長） */
  readonly length: AutoOrManual<number>;
  /** Checksum（16 ビット、自動時は IPv4 擬似ヘッダ含む RFC 768 チェックサム） */
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
  /** Data Offset（4 ビット、自動時はオプションなし基本ヘッダの 5） */
  readonly dataOffset: AutoOrManual<number>;
  /** Control Bits（8 ビット、RFC 9293 Section 3.1） */
  readonly flags: TCPFlags;
  /** Window Size（16 ビット、0〜65535） */
  readonly windowSize: number;
  /** Checksum（16 ビット、自動時は IPv4 擬似ヘッダ含む RFC 9293 チェックサム） */
  readonly checksum: AutoOrManual<number>;
  /** Urgent Pointer（16 ビット、0〜65535） */
  readonly urgentPointer: number;
}

export type Layer = EthernetLayer | IPv4Layer | ICMPLayer | UDPLayer | TCPLayer;

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
