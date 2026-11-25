import { writeUint16BE } from './bytes';
import { err, ok, type Result } from './result';

/**
 * RFC 1071 に従い、16 ビットのインターネットチェックサムを計算する。
 *
 * - バイト列はネットワークバイトオーダー（ビッグエンディアン）の 16 ビット語列として扱う。
 * - バイト長が奇数の場合は、末尾に 0x00 を補って 16 ビット語にする。
 * - 1 の補数和を取り、その 1 の補数を 0x0000〜0xffff の整数で返す。
 */
export function internetChecksum(bytes: Uint8Array): number {
  let sum = 0;

  for (let i = 0; i < bytes.length; i += 2) {
    const high = bytes[i];
    const low = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const word = (high << 8) | low;
    sum += word;
    // 毎回 16 ビットに折り畳むことで、長いバイト列でも 32 ビットオーバーフローを防ぐ
    if (sum > 0xffff) {
      sum = (sum & 0xffff) + (sum >>> 16);
    }
  }

  return (~sum) & 0xffff;
}

export interface IPv4PseudoHeaderParams {
  /** 送信元 IPv4 アドレス（4 バイト） */
  readonly srcIp: Uint8Array;
  /** 宛先 IPv4 アドレス（4 バイト） */
  readonly dstIp: Uint8Array;
  /** IPv4 プロトコル番号（例: TCP=6, UDP=17） */
  readonly protocol: number;
  /** チェックサム対象の上位層バイト列（ヘッダ＋ペイロード、チェックサム欄は 0 埋め） */
  readonly segment: Uint8Array;
}

/**
 * IPv4 擬似ヘッダ（RFC 768 / RFC 9293）を先頭に付与したうえで
 * RFC 1071 インターネットチェックサムを計算する。
 *
 * 注意: UDP における「計算結果が 0x0000 のときは 0xffff を格納する（RFC 768）」変換は
 * TCP（RFC 9293）には適用されないため、本関数は生のチェックサム値を返す。
 */
export function ipv4PseudoHeaderChecksum(params: IPv4PseudoHeaderParams): Result<number> {
  const { srcIp, dstIp, protocol, segment } = params;

  if (srcIp.length !== 4) {
    return err(`送信元 IPv4 アドレスは 4 バイトである必要があります（現在 ${srcIp.length} バイト）。`);
  }
  if (dstIp.length !== 4) {
    return err(`宛先 IPv4 アドレスは 4 バイトである必要があります（現在 ${dstIp.length} バイト）。`);
  }
  if (!Number.isInteger(protocol) || protocol < 0 || protocol > 0xff) {
    return err(`プロトコル番号は 0〜255 の整数で指定してください（現在 ${protocol}）。`);
  }
  if (segment.length > 0xffff) {
    return err(
      `上位層セグメント長が 65535 バイトを超えています（現在 ${segment.length} バイト）。`,
    );
  }

  // IPv4 擬似ヘッダ（12 バイト）+ セグメント本体
  const buffer = new Uint8Array(12 + segment.length);
  buffer.set(srcIp, 0);
  buffer.set(dstIp, 4);
  buffer[8] = 0;
  buffer[9] = protocol;
  writeUint16BE(buffer, 10, segment.length);
  buffer.set(segment, 12);

  return ok(internetChecksum(buffer));
}
