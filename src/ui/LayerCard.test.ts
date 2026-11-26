import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { FIELD_DOCS } from '../core/fieldDocs';
import { autoValue, type Layer } from '../core/layers/types';
import { buildPacket } from '../core/packet';
import {
  createDefaultARP,
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultGRE,
  createDefaultICMP,
  createDefaultICMPv6,
  createDefaultIPv4,
  createDefaultIPv6,
  createDefaultTCP,
  createDefaultUDP,
  createDefaultVLAN,
  createDefaultVXLAN,
} from '../core/presets';
import { LayerCard } from './LayerCard';

describe('LayerCard per-field info controls', () => {
  it('renders a keyboard-accessible info control (aria-expanded & aria-controls) for every documented field', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      createDefaultVLAN(),
      createDefaultARP(),
      {
        ...createDefaultIPv4(),
        options: [
          { kind: 'routerAlert', value: 0 },
          { kind: 'rr', pointer: autoValue(), addresses: ['192.0.2.1'] },
          { kind: 'timestamp', pointer: 5, overflow: 0, flag: 0, dataHex: '00 00 00 01' },
          { kind: 'nop' },
          { kind: 'raw', optionType: 134, length: autoValue(), dataHex: 'aa bb' },
          { kind: 'eol' },
        ],
      },
      {
        ...createDefaultIPv4(),
        options: [
          { kind: 'lsrr', pointer: autoValue(), addresses: ['192.0.2.1'] },
          { kind: 'ssrr', pointer: autoValue(), addresses: ['192.0.2.2'] },
        ],
      },
      createDefaultIPv6(),
      createDefaultICMP(),
      createDefaultICMPv6(),
      {
        ...createDefaultICMPv6(),
        icmpType: 2,
        rest: { kind: 'raw', value: 1280 },
      },
      {
        ...createDefaultGRE(),
        checksumPresent: true,
        keyPresent: true,
        sequencePresent: true,
        key: 0x11223344,
        sequenceNumber: 1,
      },
      createDefaultUDP(),
      {
        ...createDefaultTCP(),
        options: [
          { kind: 'mss', mss: 1460 },
          { kind: 'windowScale', shiftCount: 7 },
          { kind: 'sackPermitted' },
          { kind: 'timestamps', tsVal: 100, tsEcr: 0 },
          { kind: 'nop' },
          { kind: 'raw', optionKind: 30, length: autoValue(), dataHex: 'aa bb' },
          { kind: 'eol' },
        ],
      },
      {
        ...createDefaultTCP(),
        options: [{ kind: 'sack', blocks: [{ left: 100, right: 200 }] }],
      },
      createDefaultVXLAN(),
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
          /<button[^>]*aria-expanded="false"[^>]*aria-controls="layer-\d+-([a-zA-Z0-9-]+)-doc"[^>]*>/g,
        ),
      ];
      let set = renderedControlsByLayer.get(layer.type);
      if (!set) {
        set = new Set<string>();
        renderedControlsByLayer.set(layer.type, set);
      }
      for (const m of matches) {
        // Normalize hyphenated indexed IDs (e.g., options-0-sack-blocks-0-left -> options.sack.blocks.left)
        const normalized = m[1].includes('-')
          ? m[1].replace(/-\d+(?=-|$)/g, '').replace(/-/g, '.')
          : m[1];
        set.add(normalized);
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
