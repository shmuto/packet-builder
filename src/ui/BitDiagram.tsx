import { useMemo } from 'react';
import {
  buildBitDiagramRows,
  doesSpanMatchHighlight,
  type HighlightTarget,
} from '../core/inspector';
import type { FieldSpan, Layer } from '../core/layers/types';
import { LAYER_META } from './layerMeta';

export interface BitDiagramProps {
  readonly layers: readonly Layer[];
  readonly spans: readonly FieldSpan[];
  readonly selectedLayerIndex: number;
  readonly highlight: HighlightTarget | null;
  readonly onSelectLayer: (index: number) => void;
  readonly onHighlightChange: (target: HighlightTarget | null) => void;
}

const RULER_TICKS = [0, 4, 8, 12, 16, 20, 24, 28];

/**
 * RFC-style 32-bit header bit diagram for the selected protocol layer.
 * Cells synchronize bidirectionally with the editor fields and hex dump bytes.
 */
export function BitDiagram({
  layers,
  spans,
  selectedLayerIndex,
  highlight,
  onSelectLayer,
  onHighlightChange,
}: BitDiagramProps) {
  const safeIndex =
    selectedLayerIndex >= 0 && selectedLayerIndex < layers.length ? selectedLayerIndex : 0;

  const diagramRows = useMemo(
    () => buildBitDiagramRows(spans, safeIndex),
    [spans, safeIndex],
  );

  if (layers.length === 0 || diagramRows.length === 0) {
    return null;
  }

  const activeLayer = layers[safeIndex];
  const meta = LAYER_META[activeLayer.type];

  return (
    <div className="bit-diagram-section" aria-label="32-bit header layout diagram">
      <div className="bit-diagram-header">
        <div>
          <h3 className="bit-diagram-title">Header Bit Layout (32-bit RFC View)</h3>
          <p className="bit-diagram-sub">
            {meta.name} · {meta.rfc}
          </p>
        </div>
        <div className="bit-diagram-tabs" role="tablist" aria-label="Select layer bit layout">
          {layers.map((layer, index) => (
            <button
              key={`${index}-${layer.type}`}
              type="button"
              role="tab"
              aria-selected={index === safeIndex}
              className={`bit-tab${index === safeIndex ? ' is-active' : ''}`}
              onClick={() => onSelectLayer(index)}
            >
              {LAYER_META[layer.type].shortName}
            </button>
          ))}
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

        <div className="bit-rows">
          {diagramRows.map((row) => (
            <div key={row.rowIndex} className="bit-row">
              <span className="bit-row-label" aria-hidden="true">
                +{row.bitOffsetInLayer}
              </span>
              <div className="bit-row-grid">
                {row.cells.map((cell) => {
                  const active = doesSpanMatchHighlight(cell.span, highlight);
                  const startBit = cell.span.bitOffset;
                  const endBit = startBit + cell.span.bitLength - 1;

                  return (
                    <button
                      key={`${row.rowIndex}-${cell.colStart}-${cell.span.fieldId}`}
                      type="button"
                      className={`bit-cell layer-tint-${activeLayer.type}${active ? ' is-highlighted' : ''}${cell.isContinuation ? ' is-continuation' : ''}`}
                      style={{
                        gridColumn: `${cell.colStart + 1} / span ${cell.colSpan}`,
                      }}
                      title={`${cell.span.label} (${cell.span.bitLength} bits, packet bits ${startBit}..${endBit})`}
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
