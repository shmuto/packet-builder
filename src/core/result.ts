/**
 * 成功またはエラーを表す戻り値の型。
 * 不正な入力に対して例外を投げず、エラー内容を呼び出し元へ返すために使う。
 */
export type Result<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

/** 成功結果を生成する */
export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

/** エラー結果を生成する */
export function err<T = never>(error: string): Result<T> {
  return { ok: false, error };
}
