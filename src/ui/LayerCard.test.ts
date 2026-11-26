import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { FIELD_DOCS } from '../core/fieldDocs';
import type { Layer } from '../core/layers/types';
import { buildPacket } from '../core/packet';
import {
  createDefaultARP,
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultICMP,
  createDefaultIPv4,
  createDefaultTCP,
  createDefaultUDP,
} from '../core/presets';
import { LayerCard } from './LayerCard';

describe('LayerCard per-field info controls', () => {
  it('renders a keyboard-accessible info control (aria-expanded & aria-controls) for every documented field', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultARP(),
      createDefaultIPv4(),
      createDefaultICMP(),
      createDefaultUDP(),
      createDefaultTCP(),
      { ...createDefaultBGP(), bgpType: 1 },
      { ...createDefaultBGP(), bgpType: 2 },
      { ...createDefaultBGP(), bgpType: 3 },
      { ...createDefaultBGP(), bgpType: 4 },
    ];

    const built = buildPacket(layers, new Uint8Array(0));
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const renderedControlsByLayer = new Map<string, Set<string>>();

    layers.forEach((layer, index) => {
      const id = `layer-${index}`;
      const html = renderToStaticMarkup(
        createElement(LayerCard, {
          id,
          index,
          total: layers.length,
          layer,
          spans: built.spans,
          highlight: null,
          resolvedAutoValues: built.resolvedAutoValues[index],
          errors: [],
          warnings: [],
          onHighlightChange: () => {},
          onChange: () => {},
          onMoveUp: () => {},
          onMoveDown: () => {},
          onRemove: () => {},
        }),
      );

      const matches = [
        ...html.matchAll(
          /<button[^>]*aria-expanded="false"[^>]*aria-controls="layer-\d+-([a-zA-Z0-9]+)-doc"[^>]*>/g,
        ),
      ];
      let set = renderedControlsByLayer.get(layer.type);
      if (!set) {
        set = new Set<string>();
        renderedControlsByLayer.set(layer.type, set);
      }
      for (const m of matches) {
        set.add(m[1]);
      }
    });

    for (const [layerType, docs] of Object.entries(FIELD_DOCS)) {
      const rendered = renderedControlsByLayer.get(layerType) ?? new Set<string>();
      for (const fieldId of Object.keys(docs)) {
        expect(
          rendered.has(fieldId),
          `Expected accessible info control for ${layerType}.${fieldId}`,
        ).toBe(true);
      }
    }
  });
});
