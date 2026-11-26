import { describe, expect, it } from 'vitest';
import { ADDABLE_LAYER_TYPES, formatSupportedLayersList, LAYER_META } from './layerMeta';

describe('formatSupportedLayersList', () => {
  it('generates the header protocol list dynamically from ADDABLE_LAYER_TYPES and LAYER_META', () => {
    const formatted = formatSupportedLayersList();
    const expectedNames = ADDABLE_LAYER_TYPES.map((type) => LAYER_META[type].name);

    for (const name of expectedNames) {
      expect(formatted).toContain(name);
    }
    expect(formatted).toBe(
      `${expectedNames.slice(0, -1).join(', ')}, and ${expectedNames[expectedNames.length - 1]}`,
    );
  });
});
