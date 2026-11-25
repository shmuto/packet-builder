import { err, ok, type Result } from './result';

const MAC_OCTET_PATTERN = /^[0-9a-fA-F]{2}$/;
const IPV4_OCTET_PATTERN = /^(0|[1-9][0-9]{0,2})$/;
const HEX_ONLY_PATTERN = /^[0-9a-fA-F]*$/;
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
 * 各オクテットは 0〜255 の 10 進数とし、先頭ゼロ（例: 01）はエラーとする。
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
 * 16 進文字列（空白・改行による区切りを許容）をバイト列に変換する。
 * 空文字列および空白のみの文字列は長さ 0 のバイト列を返す。
 */
export function parseHexBytes(text: string): Result<Uint8Array> {
  const compact = text.replace(/\s+/g, '');
  if (compact.length === 0) {
    return ok(new Uint8Array(0));
  }

  if (!HEX_ONLY_PATTERN.test(compact)) {
    return err('16 進数（0-9, a-f, A-F）と空白以外の文字が含まれています。');
  }

  if (compact.length % 2 !== 0) {
    return err(
      `16 進文字列の桁数が奇数（${compact.length} 桁）です。1 バイトあたり 2 桁で指定してください。`,
    );
  }

  const bytes = new Uint8Array(compact.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  }

  return ok(bytes);
}

/** UTF-8 テキストをバイト列に変換する */
export function encodeUtf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** 複数のバイト列を順に連結した新しい Uint8Array を返す */
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

/**
 * 16 ビット符号なし整数をネットワークバイトオーダー（ビッグエンディアン）で書き込む。
 */
export function writeUint16BE(target: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(offset) || offset < 0 || offset + 2 > target.length) {
    throw new RangeError(`書き込み位置が範囲外です（offset=${offset}, length=${target.length}）。`);
  }
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`uint16 の範囲外です（value=${value}）。0〜65535 の整数を指定してください。`);
  }
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

/**
 * 32 ビット符号なし整数をネットワークバイトオーダー（ビッグエンディアン）で書き込む。
 */
export function writeUint32BE(target: Uint8Array, offset: number, value: number): void {
  if (!Number.isInteger(offset) || offset < 0 || offset + 4 > target.length) {
    throw new RangeError(`書き込み位置が範囲外です（offset=${offset}, length=${target.length}）。`);
  }
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(
      `uint32 の範囲外です（value=${value}）。0〜4294967295 の整数を指定してください。`,
    );
  }
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

/** バイト列を空白なしの小文字 16 進文字列へ変換する */
export function toHexString(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * バイト列を 16 バイトごとに改行し、行頭に 16 進オフセットを付けたダンプ文字列を返す。
 * オフセット桁数は最小 4 桁とし、65537 バイト以上（最終行オフセットが 0x10000 以上）のデータでは最終行の桁数に合わせて全行を揃える。
 * 空のバイト列に対しては空文字列を返す。
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
