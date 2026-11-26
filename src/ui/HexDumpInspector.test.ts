import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { evaluatePacketDraft } from '../core/inspector';
import { createPresets } from '../core/presets';
import { ok } from '../core/result';
import { HexDumpInspector } from './HexDumpInspector';

describe('HexDumpInspector', () => {
  it('renders 16 aligned hex column header cells (00-0f) with is-mid-gap only on column 07', () => {
    const preset = createPresets()[0];
    const draft = evaluatePacketDraft(preset.layers, ok(preset.payloadBytes));

    const html = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        onHighlightChange: () => {},
      }),
    );

    const headMatch = html.match(/<div class="hexdump-head"[^>]*>([\s\S]*?)<\/div>/);
    expect(headMatch).not.toBeNull();

    const cellMatches = [
      ...headMatch![1].matchAll(/<span class="([^"]*hex-byte-head[^"]*)">([0-9a-f]{2})<\/span>/g),
    ];

    expect(cellMatches).toHaveLength(16);
    expect(cellMatches.map((m) => m[2])).toEqual([
      '00', '01', '02', '03', '04', '05', '06', '07',
      '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
    ]);

    cellMatches.forEach((m, idx) => {
      const hasMidGap = m[1].split(/\s+/).includes('is-mid-gap');
      expect(hasMidGap).toBe(idx === 7);
    });
  });
});
