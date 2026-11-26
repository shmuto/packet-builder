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
  createDefaultICMPv6,
  createDefaultIPv4,
  createDefaultIPv6,
  createDefaultTCP,
  createDefaultUDP,
  createDefaultVLAN,
} from '../core/presets';
import { LayerCard } from './LayerCard';

describe('LayerCard per-field info controls', () => {
  it('renders a keyboard-accessible info control (aria-expanded & aria-controls) for every documented field', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultVLAN(),
      createDefaultARP(),
      createDefaultIPv4(),
      createDefaultIPv6(),
      createDefaultICMP(),
      createDefaultICMPv6(),
      {
        ...createDefaultICMPv6(),
        icmpType: 2,
        rest: { kind: 'raw', value: 1280 },
      },
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

    // ICMPv6 Type 2 (Packet Too Big) renders the RFC 4443 §3.2 MTU label
    const ptbLayer = {
      ...createDefaultICMPv6(),
      icmpType: 2,
      rest: { kind: 'raw' as const, value: 1280 },
    };
    const ptbBuilt = buildPacket([createDefaultIPv6(), ptbLayer], new Uint8Array(0));
    expect(ptbBuilt.ok).toBe(true);
    if (ptbBuilt.ok) {
      const ptbHtml = renderToStaticMarkup(
        createElement(LayerCard, {
          id: 'layer-ptb',
          index: 1,
          total: 2,
          layer: ptbLayer,
          spans: ptbBuilt.spans,
          highlight: null,
          resolvedAutoValues: ptbBuilt.resolvedAutoValues[1],
          errors: [],
          warnings: [],
          onHighlightChange: () => {},
          onChange: () => {},
          onMoveUp: () => {},
          onMoveDown: () => {},
          onRemove: () => {},
        }),
      );
      expect(ptbHtml).toContain('>MTU<');
    }
  });
});
