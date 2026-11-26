import type { BaseLayer, LayerRegistry } from './layers/definition';
import { getDefaultLayerRegistry } from './layers/registry';
import type { FieldDoc, LayerType } from './layers/types';

export type { FieldDoc };

/**
 * Exhaustive per-field documentation map keyed by LayerType and FieldSpan.fieldId,
 * built automatically from the core layer registry.
 */
export const FIELD_DOCS: Readonly<Record<LayerType, Readonly<Record<string, FieldDoc>>>> =
  getDefaultLayerRegistry().fieldDocs as Readonly<
    Record<LayerType, Readonly<Record<string, FieldDoc>>>
  >;

const INDEX_BRACKET_PATTERN = /\[\d+\]/g;

/**
 * Normalizes indexed option field IDs (e.g., `options[0].mss.mss`, `options[2].sack.blocks[1].left`)
 * into canonical FIELD_DOCS keys (`options.mss.mss`, `options.sack.blocks.left`).
 */
export function normalizeFieldDocId(fieldId: string): string {
  return fieldId.replace(INDEX_BRACKET_PATTERN, '');
}

/**
 * Looks up the beginner-friendly summary and specification reference for a header field
 * against any layer registry (defaults to the built-in registry).
 */
export function getFieldDocFromRegistry<L extends BaseLayer>(
  registry: LayerRegistry<L>,
  layerType: string,
  fieldId: string,
): FieldDoc | undefined {
  const layerDocs = registry.fieldDocs[layerType];
  if (!layerDocs) return undefined;
  if (Object.prototype.hasOwnProperty.call(layerDocs, fieldId)) {
    return layerDocs[fieldId];
  }
  const normalized = normalizeFieldDocId(fieldId);
  if (normalized !== fieldId && Object.prototype.hasOwnProperty.call(layerDocs, normalized)) {
    return layerDocs[normalized];
  }
  return undefined;
}

/**
 * Looks up the beginner-friendly summary and specification reference for a header field.
 * Resolves both direct field IDs and indexed option field IDs.
 */
export function getFieldDoc(layerType: LayerType, fieldId: string): FieldDoc | undefined {
  return getFieldDocFromRegistry(getDefaultLayerRegistry(), layerType, fieldId);
}
