import { decodeUtf8Strict } from './bytes';
import { createDecodeContext } from './layers/decodeHelpers';
import type { BaseLayer, DecodeLayerContext, LayerRegistry } from './layers/definition';
import { getDefaultLayerRegistry } from './layers/registry';
import type { Layer } from './layers/types';
import { err, ok, type Result } from './result';

export type DecodeStartLayer = 'ethernet' | 'ipv4' | 'ipv6';

export interface DecodedPacket<L extends BaseLayer = Layer> {
  readonly layers: readonly L[];
  readonly payload: Uint8Array;
  /** Informational notes about unsupported/truncated or non-base header fields */
  readonly notes: readonly string[];
}

/**
 * Decodes raw packet bytes into a stack of tsumiki Layer objects and a Payload.
 * Preserves auto vs. manual field status so re-encoding reproduces the exact input bytes.
 */
export function decodePacket(
  bytes: Uint8Array,
  startLayer?: DecodeStartLayer,
): Result<DecodedPacket<Layer>>;
export function decodePacket<L extends BaseLayer>(
  bytes: Uint8Array,
  startLayer: string,
  registry: LayerRegistry<L>,
): Result<DecodedPacket<L>>;
export function decodePacket<L extends BaseLayer>(
  bytes: Uint8Array,
  startLayer: string = 'ethernet',
  registry: LayerRegistry<L> = getDefaultLayerRegistry() as unknown as LayerRegistry<L>,
): Result<DecodedPacket<L>> {
  if (bytes.length === 0) {
    return err('Input packet is empty. Paste hexadecimal packet bytes to decode.');
  }

  const def = registry.get(startLayer);
  if (!def || !def.decodeStart) {
    return err(`Unsupported start layer "${startLayer}".`);
  }

  const notes: string[] = [];
  const ctx = createDecodeContext(registry.tables, notes, {
    carrier: 'start',
    enclosingLabel: startLayer,
    vlanDepth: 0,
    tunnelDepth: 0,
  });

  const decoded = def.decodeStart(bytes, ctx as unknown as DecodeLayerContext<BaseLayer>);
  if (!decoded.ok) {
    return decoded;
  }

  return ok({
    layers: decoded.value.layers as readonly L[],
    payload: decoded.value.payload,
    notes,
  });
}

export type PrintableUtf8Result =
  | { readonly printable: true; readonly text: string }
  | { readonly printable: false };

// Reject C0/DEL control chars (except \t, \n, \r) and UTF-8 BOM so binary payloads stay in Hex mode
const NON_PRINTABLE_OR_BOM_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\ufeff]/;

/**
 * Checks whether decoded payload bytes can be safely edited in Text (UTF-8) mode
 * without hiding binary control characters or a leading BOM.
 */
export function detectPrintableUtf8(bytes: Uint8Array): PrintableUtf8Result {
  if (bytes.length === 0) {
    return { printable: true, text: '' };
  }
  const decoded = decodeUtf8Strict(bytes);
  if (!decoded.ok) {
    return { printable: false };
  }
  if (NON_PRINTABLE_OR_BOM_PATTERN.test(decoded.value)) {
    return { printable: false };
  }
  return { printable: true, text: decoded.value };
}
