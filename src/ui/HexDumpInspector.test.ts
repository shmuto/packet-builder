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

  it('shows round-trip info note only for differs and unsupported-start reports', () => {
    const preset = createPresets()[0];
    const draft = evaluatePacketDraft(preset.layers, ok(preset.payloadBytes));

    const reproducibleHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: { kind: 'reproducible' },
        onHighlightChange: () => {},
      }),
    );
    expect(reproducibleHtml).not.toContain('export-status-info');

    const notBuiltHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: { kind: 'not-built' },
        onHighlightChange: () => {},
      }),
    );
    expect(notBuiltHtml).not.toContain('export-status-info');

    const differsHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: {
          kind: 'differs',
          decodedLayerTypes: ['ethernet', 'ipv4', 'udp'],
          decodedPayloadLength: 42,
        },
        onHighlightChange: () => {},
      }),
    );
    expect(differsHtml).toContain('export-status-info');
    expect(differsHtml).toContain(
      'Import Hex will read these bytes as ETH -&gt; IPv4 -&gt; UDP + Payload (42 bytes). Use Copy Link to keep the exact stack.',
    );

    const unsupportedHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: {
          kind: 'unsupported-start',
          outerLayerType: 'udp',
        },
        onHighlightChange: () => {},
      }),
    );
    expect(unsupportedHtml).toContain('export-status-info');
    expect(unsupportedHtml).toContain(
      'Import Hex supports Ethernet II, Raw IPv4, or Raw IPv6 as the outermost header; this stack starts with UDP. Use Copy Link to keep the exact stack.',
    );

    const noHeadersHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: [],
        draft,
        highlight: null,
        roundTripReport: {
          kind: 'unsupported-start',
          outerLayerType: null,
        },
        onHighlightChange: () => {},
      }),
    );
    expect(noHeadersHtml).toContain(
      'Import Hex supports Ethernet II, Raw IPv4, or Raw IPv6 as the outermost header; this packet has no header layers. Use Copy Link to keep the exact stack.',
    );

    const emptyDecodedHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: {
          kind: 'differs',
          decodedLayerTypes: [],
          decodedPayloadLength: 0,
        },
        onHighlightChange: () => {},
      }),
    );
    expect(emptyDecodedHtml).toContain(
      'Import Hex cannot decode these bytes back into the same layer stack. Use Copy Link to keep the exact stack.',
    );

    const zeroPayloadHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: {
          kind: 'differs',
          decodedLayerTypes: ['ethernet', 'ipv4'],
          decodedPayloadLength: 0,
        },
        onHighlightChange: () => {},
      }),
    );
    expect(zeroPayloadHtml).toContain(
      'Import Hex will read these bytes as ETH -&gt; IPv4. Use Copy Link to keep the exact stack.',
    );

    const oneBytePayloadHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        roundTripReport: {
          kind: 'differs',
          decodedLayerTypes: ['ethernet'],
          decodedPayloadLength: 1,
        },
        onHighlightChange: () => {},
      }),
    );
    expect(oneBytePayloadHtml).toContain(
      'Import Hex will read these bytes as ETH + Payload (1 byte). Use Copy Link to keep the exact stack.',
    );
  });

  it('displays field summary and RFC reference in the hover detail strip for highlighted fields and single-field bytes', () => {
    const preset = createPresets()[0]; // Ethernet (0) + IPv4 (1) + UDP (2)
    const draft = evaluatePacketDraft(preset.layers, ok(preset.payloadBytes));

    // Highlight IPv4 TTL field (layerIndex 1, fieldId 'ttl')
    const fieldHighlightHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: { kind: 'field', layerIndex: 1, fieldId: 'ttl' },
        onHighlightChange: () => {},
      }),
    );
    expect(fieldHighlightHtml).toContain('hover-detail-doc');
    expect(fieldHighlightHtml).toContain('Hop limit decremented by each router');
    expect(fieldHighlightHtml).toContain('RFC 791 §3.1');

    // Highlight byte #22 (IPv4 TTL byte: 14 Ethernet + 8 IPv4 offset)
    const byteHighlightHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: { kind: 'byte', byteIndex: 22 },
        onHighlightChange: () => {},
      }),
    );
    expect(byteHighlightHtml).toContain('hover-detail-doc');
    expect(byteHighlightHtml).toContain('RFC 791 §3.1');

    // Highlight payload field: no RFC field doc should appear
    const payloadHighlightHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: { kind: 'field', layerIndex: 3, fieldId: 'payload' },
        onHighlightChange: () => {},
      }),
    );
    expect(payloadHighlightHtml).not.toContain('hover-detail-doc');
  });

  it('renders Import Hex inside the export toolbar when onToggleImport is provided and reveals importPanel when open', () => {
    const preset = createPresets()[0];
    const draft = evaluatePacketDraft(preset.layers, ok(preset.payloadBytes));

    const closedHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        showImportPanel: false,
        onToggleImport: () => {},
        importPanel: createElement('div', { className: 'import-panel' }, 'Panel Content'),
        onHighlightChange: () => {},
      }),
    );
    expect(closedHtml).toContain('Import Hex');
    expect(closedHtml).toContain('aria-expanded="false"');
    expect(closedHtml).not.toContain('Panel Content');

    const openHtml = renderToStaticMarkup(
      createElement(HexDumpInspector, {
        layers: preset.layers,
        draft,
        highlight: null,
        showImportPanel: true,
        onToggleImport: () => {},
        importPanel: createElement('div', { className: 'import-panel' }, 'Panel Content'),
        onHighlightChange: () => {},
      }),
    );
    expect(openHtml).toContain('aria-expanded="true"');
    expect(openHtml).toContain('Panel Content');
  });
});
