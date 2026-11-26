import { err, ok, type Result } from '../result';
import type { AutoOrManual, RawOptionLength } from './types';

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function validateExactKeys(
  value: unknown,
  expectedKeys: readonly string[],
  context: string,
): Result<Record<string, unknown>> {
  if (!isPlainObject(value)) {
    return err(`${context} must be an object.`);
  }
  const ownKeys = Object.keys(value);
  for (const key of ownKeys) {
    if (FORBIDDEN_KEYS.has(key)) {
      return err(`${context} contains forbidden key "${key}".`);
    }
  }
  const expectedSet = new Set(expectedKeys);
  for (const key of ownKeys) {
    if (!expectedSet.has(key)) {
      return err(`${context} has unexpected key "${key}".`);
    }
  }
  for (const key of expectedKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      return err(`${context} is missing required key "${key}".`);
    }
  }
  return ok(value);
}

export function expectString(
  obj: Record<string, unknown>,
  key: string,
  context: string,
): Result<string> {
  const value = obj[key];
  if (typeof value !== 'string') {
    return err(`${context}.${key} must be a string.`);
  }
  return ok(value);
}

export function expectNumber(
  obj: Record<string, unknown>,
  key: string,
  context: string,
): Result<number> {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return err(`${context}.${key} must be a finite number.`);
  }
  return ok(value);
}

export function expectBoolean(
  obj: Record<string, unknown>,
  key: string,
  context: string,
): Result<boolean> {
  const value = obj[key];
  if (typeof value !== 'boolean') {
    return err(`${context}.${key} must be a boolean.`);
  }
  return ok(value);
}

export function validateAutoOrManualNumber(
  raw: unknown,
  context: string,
): Result<AutoOrManual<number>> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const mode = raw.mode;
  if (mode === 'auto') {
    const checked = validateExactKeys(raw, ['mode'], context);
    if (!checked.ok) return checked;
    return ok({ mode: 'auto' });
  }
  if (mode === 'manual') {
    const checked = validateExactKeys(raw, ['mode', 'value'], context);
    if (!checked.ok) return checked;
    const val = expectNumber(checked.value, 'value', context);
    if (!val.ok) return val;
    return ok({ mode: 'manual', value: val.value });
  }
  return err(`${context}.mode must be "auto" or "manual".`);
}

export function validateAutoOrManualString(
  raw: unknown,
  context: string,
): Result<AutoOrManual<string>> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  const mode = raw.mode;
  if (mode === 'auto') {
    const checked = validateExactKeys(raw, ['mode'], context);
    if (!checked.ok) return checked;
    return ok({ mode: 'auto' });
  }
  if (mode === 'manual') {
    const checked = validateExactKeys(raw, ['mode', 'value'], context);
    if (!checked.ok) return checked;
    const val = expectString(checked.value, 'value', context);
    if (!val.ok) return val;
    return ok({ mode: 'manual', value: val.value });
  }
  return err(`${context}.mode must be "auto" or "manual".`);
}

export const MAX_PERMALINK_OPTIONS = 64;
export const MAX_PERMALINK_OPTION_ITEMS = 64;

export function validateRawOptionLength(
  raw: unknown,
  context: string,
): Result<RawOptionLength> {
  if (!isPlainObject(raw)) {
    return err(`${context} must be an object.`);
  }
  if (raw.mode === 'none') {
    const checked = validateExactKeys(raw, ['mode'], context);
    if (!checked.ok) return checked;
    return ok({ mode: 'none' });
  }
  return validateAutoOrManualNumber(raw, context);
}
