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

  it('keeps Copy Link enabled for broken packets and shows a note only when URL exceeds 8000 chars', () => {
    const preset = createPresets()[0];
    const brokenLayers = preset.layers.map((layer) =>
      layer.type === 'ipv4' ? { ...layer, ttl: 999 } : layer,
    );
    const brokenDraft = evaluatePacketDraft(brokenLayers, ok(preset.payloadBytes));
    expect(brokenDraft.ok).toBe(false);

    const shortUrl = 'https://shmuto.github.io/packet-builder/#p1=abc';
    const shortHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: brokenLayers,
        draft: brokenDraft,
        highlight: null,
        permalinkUrl: shortUrl,
        onHighlightChange: () => {},
      }),
    );

    const copyLinkBtn = shortHtml.match(/<button[^>]*>Copy Link<\/button>/);
    expect(copyLinkBtn).not.toBeNull();
    expect(copyLinkBtn![0]).not.toContain('disabled');
    expect(shortHtml).not.toContain('export-status-note');

    const exactLimitUrl = 'https://example.com/#' + 'a'.repeat(8000 - 'https://example.com/#'.length);
    expect(exactLimitUrl.length).toBe(8000);
    const exactLimitHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: brokenLayers,
        draft: brokenDraft,
        highlight: null,
        permalinkUrl: exactLimitUrl,
        onHighlightChange: () => {},
      }),
    );
    expect(exactLimitHtml).not.toContain('export-status-note');

    const longUrl = exactLimitUrl + 'a';
    expect(longUrl.length).toBe(8001);
    const longHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: brokenLayers,
        draft: brokenDraft,
        highlight: null,
        permalinkUrl: longUrl,
        onHighlightChange: () => {},
      }),
    );
    expect(longHtml).toContain('export-status-note');
  });
});
