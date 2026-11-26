import { decodeUtf8Strict, encodeUtf8, parseHexBytes } from './bytes';
import type { BaseLayer, LayerRegistry } from './layers/definition';
import {
  expectString,
  isPlainObject,
  validateExactKeys,
} from './layers/permalinkHelpers';
import { getDefaultLayerRegistry } from './layers/registry';
import type { Layer } from './layers/types';
import { err, ok, type Result } from './result';

export const PERMALINK_VERSION = 1;
export const PERMALINK_PREFIX = `p${PERMALINK_VERSION}=`;
export const MAX_PERMALINK_LAYERS = 64;
export const MAX_PERMALINK_PAYLOAD_BYTES = 65535;
export const PERMALINK_LONG_URL_THRESHOLD = 8000;

export type PermalinkPayload =
  | { readonly mode: 'text'; readonly text: string }
  | { readonly mode: 'hex'; readonly hex: string };

export interface PermalinkState<L extends BaseLayer = Layer> {
  readonly layers: readonly L[];
  readonly payload: PermalinkPayload;
}

const FRAGMENT_VERSION_PATTERN = /^p([0-9]+)=(.*)$/s;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

function bytesToBase64Url(bytes: Uint8Array): string {
  // Convert in chunks to avoid call stack limits on large payloads (up to 65535 bytes)
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    let chunk = '';
    for (let j = 0; j < slice.length; j++) {
      chunk += String.fromCharCode(slice[j]);
    }
    binary += chunk;
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(encoded: string): Result<Uint8Array> {
  if (encoded.length === 0) {
    return err('Permalink data is empty.');
  }
  if (!BASE64URL_PATTERN.test(encoded) || encoded.length % 4 === 1) {
    return err('Invalid base64url encoding in permalink.');
  }
  const padded =
    encoded.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (encoded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return err('Invalid base64url encoding in permalink.');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return ok(bytes);
}

/**
 * Encodes a packet builder state into a versioned URL fragment (`p1=<base64url(UTF-8 JSON)>`).
 */
export function encodePermalink<L extends BaseLayer = Layer>(state: PermalinkState<L>): string {
  const canonical: PermalinkState<L> = {
    layers: state.layers,
    payload: state.payload,
  };
  const json = JSON.stringify(canonical);
  return `${PERMALINK_PREFIX}${bytesToBase64Url(encodeUtf8(json))}`;
}

/**
 * Builds a full shareable URL that preserves any sub-path (such as GitHub Pages `/repo/`).
 */
export function buildPermalinkUrl(origin: string, pathname: string, fragment: string): string {
  const normalized = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  return `${origin}${pathname}#${normalized}`;
}

function validateLayer<L extends BaseLayer>(
  raw: unknown,
  index: number,
  registry: LayerRegistry<L>,
): Result<L> {
  const ctx = `layers[${index}]`;
  if (!isPlainObject(raw)) {
    return err(`${ctx} must be an object.`);
  }
  const type = raw.type;
  if (typeof type !== 'string') {
    return err(`${ctx}.type must be a string.`);
  }
  const def = registry.get(type);
  if (!def) {
    return err(`${ctx} has unknown layer type "${type}".`);
  }
  return def.validatePermalink(raw, ctx);
}

function validatePayload(raw: unknown): Result<PermalinkPayload> {
  const ctx = 'payload';
  if (!isPlainObject(raw)) {
    return err(`${ctx} must be an object.`);
  }
  const mode = raw.mode;
  if (mode === 'text') {
    const checked = validateExactKeys(raw, ['mode', 'text'], ctx);
    if (!checked.ok) return checked;
    const text = expectString(checked.value, 'text', ctx);
    if (!text.ok) return text;
    const byteLength = encodeUtf8(text.value).length;
    if (byteLength > MAX_PERMALINK_PAYLOAD_BYTES) {
      return err(
        `Decoded text payload exceeds maximum of ${MAX_PERMALINK_PAYLOAD_BYTES} bytes (got ${byteLength} bytes).`,
      );
    }
    return ok({ mode: 'text', text: text.value });
  }
  if (mode === 'hex') {
    const checked = validateExactKeys(raw, ['mode', 'hex'], ctx);
    if (!checked.ok) return checked;
    const hex = expectString(checked.value, 'hex', ctx);
    if (!hex.ok) return hex;
    const parsed = parseHexBytes(hex.value);
    if (parsed.ok) {
      if (parsed.value.length > MAX_PERMALINK_PAYLOAD_BYTES) {
        return err(
          `Decoded hex payload exceeds maximum of ${MAX_PERMALINK_PAYLOAD_BYTES} bytes (got ${parsed.value.length} bytes).`,
        );
      }
    } else {
      // Allow intentionally malformed hex strings to load so the normal payload error UI reports them,
      // while still bounding raw non-whitespace characters to the max payload budget.
      const compactLength = hex.value.replace(/\s+/g, '').length;
      if (compactLength > MAX_PERMALINK_PAYLOAD_BYTES * 2) {
        return err(
          `Hex payload exceeds maximum length for ${MAX_PERMALINK_PAYLOAD_BYTES} bytes.`,
        );
      }
    }
    return ok({ mode: 'hex', hex: hex.value });
  }
  return err(`${ctx}.mode must be "text" or "hex".`);
}

/**
 * Decodes and validates a permalink fragment (`p1=...` or `#p1=...`).
 * Never throws; returns `err` with a descriptive message on malformed or unsupported inputs.
 * Validates schema shape and safety limits only—out-of-range or malformed field values
 * load as-is so `buildPacket` surfaces them through the normal error UI.
 */
export function decodePermalink(fragment: string): Result<PermalinkState<Layer>>;
export function decodePermalink<L extends BaseLayer>(
  fragment: string,
  registry: LayerRegistry<L>,
): Result<PermalinkState<L>>;
export function decodePermalink<L extends BaseLayer>(
  fragment: string,
  registry: LayerRegistry<L> = getDefaultLayerRegistry() as unknown as LayerRegistry<L>,
): Result<PermalinkState<L>> {
  const normalized = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const match = FRAGMENT_VERSION_PATTERN.exec(normalized);
  if (!match) {
    return err(`Invalid permalink format: expected "${PERMALINK_PREFIX}<data>".`);
  }
  const version = match[1];
  if (version !== String(PERMALINK_VERSION)) {
    return err(
      `Unsupported permalink version "p${version}" (only "p${PERMALINK_VERSION}" is supported).`,
    );
  }

  const decodedBytes = base64UrlToBytes(match[2]);
  if (!decodedBytes.ok) {
    return decodedBytes;
  }

  const utf8 = decodeUtf8Strict(decodedBytes.value);
  if (!utf8.ok) {
    return err(`Permalink contains invalid UTF-8 (${utf8.error})`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8.value);
  } catch {
    return err('Permalink contains invalid JSON.');
  }

  const root = validateExactKeys(parsed, ['layers', 'payload'], 'permalink');
  if (!root.ok) {
    return root;
  }

  const rawLayers = root.value.layers;
  if (!Array.isArray(rawLayers)) {
    return err('permalink.layers must be an array.');
  }
  if (rawLayers.length > MAX_PERMALINK_LAYERS) {
    return err(
      `Permalink exceeds maximum of ${MAX_PERMALINK_LAYERS} layers (got ${rawLayers.length}).`,
    );
  }

  const layers: L[] = [];
  for (let i = 0; i < rawLayers.length; i++) {
    const validated = validateLayer(rawLayers[i], i, registry);
    if (!validated.ok) {
      return validated;
    }
    layers.push(validated.value);
  }

  const payload = validatePayload(root.value.payload);
  if (!payload.ok) {
    return payload;
  }

  return ok({ layers, payload: payload.value });
}

function containsNonFiniteNumber(value: unknown): boolean {
  if (typeof value === 'number') {
    return !Number.isFinite(value);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (containsNonFiniteNumber(value[i])) {
        return true;
      }
    }
    return false;
  }
  if (typeof value === 'object' && value !== null) {
    for (const entry of Object.values(value)) {
      if (containsNonFiniteNumber(entry)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Returns true if every numeric field across all layers is finite (not NaN/Infinity).
 * Used to avoid serializing transient blank numeric drafts (`NaN` -> JSON `null`) into the URL hash.
 */
export function hasOnlyFiniteNumbers(layers: readonly BaseLayer[]): boolean {
  return !containsNonFiniteNumber(layers);
}
