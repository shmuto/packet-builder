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
