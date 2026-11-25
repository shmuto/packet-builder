import { useMemo } from 'react';
import {
  buildUnifiedBitDiagramRows,
  doesSpanMatchTarget,
  resolveHighlightedLayerIndex,
  type HighlightTarget,
  type LayerSegmentSummary,
} from '../core/inspector';
import type { FieldSpan, Layer } from '../core/layers/types';
import { LAYER_META } from './layerMeta';

export interface BitDiagramProps {
  readonly layers: readonly Layer[];
  readonly spans: readonly FieldSpan[];
  readonly segments: readonly LayerSegmentSummary[];
  readonly highlight: HighlightTarget | null;
  readonly onHighlightChange: (target: HighlightTarget | null) => void;
}

const RULER_TICKS = [0, 4, 8, 12, 16, 20, 24, 28];

/**
 * Unified 32-bit RFC-style header bit diagram displaying all stacked protocol headers
 * continuously in wire order, color-coded by header with interactive range emphasis.
 */
export function BitDiagram({
  layers,
  spans,
  segments,
  highlight,
  onHighlightChange,
}: BitDiagramProps) {
  const diagramRows = useMemo(() => buildUnifiedBitDiagramRows(spans), [spans]);

  const headerSegments = useMemo(
    () => segments.filter((seg) => seg.layerType !== 'payload'),
    [segments],
  );

  const activeLayerIndex = useMemo(
    () => resolveHighlightedLayerIndex(spans, highlight),
    [spans, highlight],
  );

  if (layers.length === 0 || diagramRows.length === 0) {
    return null;
  }

  const totalHeaderBytes = headerSegments.reduce((acc, seg) => acc + seg.byteLength, 0);
  const totalHeaderBits = totalHeaderBytes * 8;

  return (
    <div className="bit-diagram-section" aria-label="Unified 32-bit header layout diagram">
      <div className="bit-diagram-header">
        <div>
          <h3 className="bit-diagram-title">Header Bit Layout (Unified 32-bit View)</h3>
          <p className="bit-diagram-sub">
            {headerSegments.length} {headerSegments.length === 1 ? 'header' : 'headers'} ·{' '}
            {totalHeaderBytes} bytes ({totalHeaderBits} bits) · color-coded by layer
          </p>
        </div>

        <div className="bit-layer-pills" role="group" aria-label="Highlight header range">
          {headerSegments.map((seg) => {
            if (seg.layerType === 'payload') return null;
            const meta = LAYER_META[seg.layerType];
            const isLayerActive = activeLayerIndex === seg.layerIndex;
            const byteEnd = seg.byteOffset + seg.byteLength - 1;
            const rangeText =
              seg.byteOffset === byteEnd ? `${seg.byteOffset}B` : `${seg.byteOffset}..${byteEnd}B`;

            return (
              <button
                key={`${seg.layerIndex}-${seg.layerType}`}
                type="button"
                className={`bit-layer-pill layer-theme-${seg.layerType}${isLayerActive ? ' is-active' : ''}`}
                title={`Highlight ${meta.name} (${meta.rfc}): ${seg.byteLength} bytes (bytes ${seg.byteOffset}..${byteEnd})`}
                onClick={() =>
                  onHighlightChange({ kind: 'layer', layerIndex: seg.layerIndex })
                }
                onMouseEnter={() =>
                  onHighlightChange({ kind: 'layer', layerIndex: seg.layerIndex })
                }
                onMouseLeave={() => onHighlightChange(null)}
                onFocus={() =>
                  onHighlightChange({ kind: 'layer', layerIndex: seg.layerIndex })
                }
                onBlur={() => onHighlightChange(null)}
              >
                <span className={`bit-layer-dot layer-bg-${seg.layerType}`} aria-hidden="true" />
                <span>{meta.shortName}</span>
                <span className="bit-layer-range mono">{rangeText}</span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="bit-diagram-frame mono">
        <div className="bit-ruler" aria-hidden="true">
          <span className="bit-row-label">bit</span>
          <div className="bit-ruler-grid">
            {RULER_TICKS.map((tick) => (
              <span
                key={tick}
                className="bit-ruler-tick"
                style={{ gridColumn: `${tick + 1} / span 4` }}
              >
                {tick}
              </span>
            ))}
          </div>
        </div>

        <div
          className="bit-rows"
          onMouseLeave={() => onHighlightChange(null)}
        >
          {diagramRows.map((row) => (
            <div key={row.rowIndex} className="bit-row">
              <span
                className="bit-row-label"
                title={`Byte 0x${row.byteOffset.toString(16).padStart(2, '0')} (packet bits ${row.bitOffset}..${row.bitOffset + row.totalBitsInRow - 1})`}
              >
                {row.bitOffset}
              </span>
              <div className="bit-row-grid">
                {row.cells.map((cell) => {
                  const isCellHighlighted = doesSpanMatchTarget(cell.span, highlight);
                  const isInActiveLayer =
                    activeLayerIndex !== null && cell.span.layerIndex === activeLayerIndex;
                  const isDimmed =
                    activeLayerIndex !== null && cell.span.layerIndex !== activeLayerIndex;
                  const startBit = cell.span.bitOffset;
                  const endBit = startBit + cell.span.bitLength - 1;
                  const layerName =
                    cell.span.layerType === 'payload'
                      ? 'Payload'
                      : LAYER_META[cell.span.layerType].name;

                  const classNames = [
                    'bit-cell',
                    `layer-theme-${cell.span.layerType}`,
                    isCellHighlighted ? 'is-highlighted' : '',
                    isInActiveLayer && !isCellHighlighted ? 'is-layer-active' : '',
                    isDimmed ? 'is-layer-dimmed' : '',
                    cell.isContinuation ? 'is-continuation' : '',
                    cell.isLayerStart ? 'is-layer-start' : '',
                    cell.isLayerEnd ? 'is-layer-end' : '',
                  ]
                    .filter(Boolean)
                    .join(' ');

                  return (
                    <button
                      key={`${row.rowIndex}-${cell.colStart}-${cell.span.layerIndex}-${cell.span.fieldId}`}
                      type="button"
                      className={classNames}
                      style={{
                        gridColumn: `${cell.colStart + 1} / span ${cell.colSpan}`,
                      }}
                      title={`${layerName} · ${cell.span.label} (${cell.span.bitLength} bits, packet bits ${startBit}..${endBit})`}
                      onMouseEnter={() =>
                        onHighlightChange({
                          kind: 'field',
                          layerIndex: cell.span.layerIndex,
                          fieldId: cell.span.fieldId,
                        })
                      }
                      onMouseLeave={() => onHighlightChange(null)}
                      onFocus={() =>
                        onHighlightChange({
                          kind: 'field',
                          layerIndex: cell.span.layerIndex,
                          fieldId: cell.span.fieldId,
                        })
                      }
                      onBlur={() => onHighlightChange(null)}
                    >
                      <span className="bit-cell-label">
                        {cell.isContinuation ? `${cell.span.label} (cont.)` : cell.span.label}
                      </span>
                      <span className="bit-cell-size">{cell.bitLengthInRow}b</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
