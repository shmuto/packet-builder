import { err, ok, type Result } from './result';

const MAC_OCTET_PATTERN = /^[0-9a-fA-F]{2}$/;
const IPV4_OCTET_PATTERN = /^(0|[1-9][0-9]{0,2})$/;
const HEX_DUMP_BYTES_PER_LINE = 16;

/**
 * `aa:bb:cc:dd:ee:ff` 形式の MAC アドレスを 6 バイトのバイト列に変換する。
 * 大文字・小文字の両方を受け付ける。
 */
export function parseMac(text: string): Result<Uint8Array> {
  if (text.length === 0) {
    return err('MAC アドレスが空です。aa:bb:cc:dd:ee:ff の形式で入力してください。');
  }

  const parts = text.split(':');
  if (parts.length !== 6) {
    return err(
      `MAC アドレスはコロン区切りの 6 バイトで指定してください（現在 ${parts.length} 個）。`,
    );
  }

  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) {
    const part = parts[i];
    if (!MAC_OCTET_PATTERN.test(part)) {
      return err(
        `MAC アドレスの ${i + 1} バイト目「${part}」が不正です。2 桁の 16 進数（00〜ff）で指定してください。`,
      );
    }
    bytes[i] = Number.parseInt(part, 16);
  }

  return ok(bytes);
}

/**
 * `192.168.0.1` 形式の IPv4 アドレスを 4 バイトのバイト列に変換する。
 * 各オクテットは 0〜255 の 10 進数で、先頭ゼロ（例: 01）はエラーとする。
 */
export function parseIPv4(text: string): Result<Uint8Array> {
  if (text.length === 0) {
    return err('IPv4 アドレスが空です。192.168.0.1 の形式で入力してください。');
  }

  const parts = text.split('.');
  if (parts.length !== 4) {
    return err(
      `IPv4 アドレスはドット区切りの 4 オクテットで指定してください（現在 ${parts.length} 個）。`,
    );
  }

  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!IPV4_OCTET_PATTERN.test(part)) {
      return err(
        `IPv4 アドレスの ${i + 1} オクテット目「${part}」が不正です。先頭ゼロなしの 0〜255 の整数で指定してください。`,
      );
    }
    const value = Number.parseInt(part, 10);
    if (value > 255) {
      return err(
        `IPv4 アドレスの ${i + 1} オクテット目「${part}」は範囲外です。0〜255 で指定してください。`,
      );
    }
    bytes[i] = value;
  }

  return ok(bytes);
}

/**
 * バイト列を 16 バイトごとに改行し、行頭に 4 桁の 16 進オフセットを付けたダンプ文字列を返す。
 * 空のバイト列に対しては空文字列を返す。
 */
export function toHexDump(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return '';
  }

  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += HEX_DUMP_BYTES_PER_LINE) {
    const end = Math.min(offset + HEX_DUMP_BYTES_PER_LINE, bytes.length);
    const hexBytes: string[] = [];
    for (let i = offset; i < end; i++) {
      hexBytes.push(bytes[i].toString(16).padStart(2, '0'));
    }
    const offsetLabel = offset.toString(16).padStart(4, '0');
    lines.push(`${offsetLabel}: ${hexBytes.join(' ')}`);
  }

  return lines.join('\n');
}
