import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toHexDump, toHexString } from '../core/bytes';
import {
  findHighlightedByteIndices,
  formatByteBinary,
  type EvaluatedPacketDraft,
  type HexDumpRow,
  type HighlightTarget,
} from '../core/inspector';
import type { Layer, LayerType } from '../core/layers/types';
import { buildPcap, selectPcapLinkType } from '../core/pcap';
import { BitDiagram } from './BitDiagram';
import { LAYER_META } from './layerMeta';

export interface HexDumpInspectorProps {
  readonly layers: readonly Layer[];
  readonly draft: EvaluatedPacketDraft;
  readonly highlight: HighlightTarget | null;
  readonly onHighlightChange: (target: HighlightTarget | null) => void;
}

type CopyStatus = 'idle' | 'hex-ok' | 'dump-ok' | 'error';

const HEX_COL_HEADERS: readonly string[] = Array.from({ length: 16 }, (_, i) =>
  i.toString(16).padStart(2, '0'),
);

function segmentShortLabel(type: LayerType | 'payload'): string {
  return type === 'payload' ? 'DATA' : LAYER_META[type].shortName;
}

function segmentFullLabel(type: LayerType | 'payload'): string {
  return type === 'payload' ? 'Payload' : LAYER_META[type].name;
}

interface HexDumpRowViewProps {
  readonly row: HexDumpRow;
  /** 16-bit bitmask of highlighted columns in this row so untouched rows skip re-rendering */
  readonly highlightMask: number;
  readonly onHoverByte: (byteIndex: number) => void;
}

const HexDumpRowView = memo(function HexDumpRowView({
  row,
  highlightMask,
  onHoverByte,
}: HexDumpRowViewProps) {
  return (
    <div className="hexdump-row">
      <span className="hexdump-offset-col">{row.offsetLabel}:</span>
      <span className="hexdump-bytes-col">
        {row.cells.map((cell, idx) => {
          const highlighted = (highlightMask & (1 << idx)) !== 0;
          return (
            <span
              key={cell.byteIndex}
              className={`hex-byte${cell.layerType ? ` layer-fg-${cell.layerType}` : ''}${idx === 7 ? ' is-mid-gap' : ''}${highlighted ? ' is-highlighted' : ''}`}
              onMouseEnter={() => onHoverByte(cell.byteIndex)}
            >
              {cell.hex}
            </span>
          );
        })}
      </span>
      <span className="hexdump-ascii-col">
        {row.cells.map((cell, idx) => {
          const highlighted = (highlightMask & (1 << idx)) !== 0;
          return (
            <span
              key={cell.byteIndex}
              className={`ascii-char${cell.layerType ? ` layer-fg-${cell.layerType}` : ''}${highlighted ? ' is-highlighted' : ''}`}
              onMouseEnter={() => onHoverByte(cell.byteIndex)}
            >
              {cell.ascii}
            </span>
          );
        })}
      </span>
    </div>
  );
});

export function HexDumpInspector({
  layers,
  draft,
  highlight,
  onHighlightChange,
}: HexDumpInspectorProps) {
  const { ok: isSuccess, bytes, spans, rows, segments, errors, warnings, payloadError } = draft;
  const totalBytes = bytes ? bytes.length : 0;
  const errorCount = errors.length + (payloadError ? 1 : 0);

  const [copyStatus, setCopyStatus] = useState<CopyStatus>('idle');
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  // Precompute highlighted byte indices once per highlight change for O(1) lookup
  const highlightedByteSet = useMemo(
    () => findHighlightedByteIndices(spans, highlight),
    [spans, highlight],
  );

  const handleHoverByte = useCallback(
    (byteIndex: number) => {
      onHighlightChange({ kind: 'byte', byteIndex });
    },
    [onHighlightChange],
  );

  const scheduleCopyReset = () => {
    if (copyTimerRef.current !== null) {
      window.clearTimeout(copyTimerRef.current);
    }
    copyTimerRef.current = window.setTimeout(() => {
      setCopyStatus('idle');
      copyTimerRef.current = null;
    }, 1800);
  };

  const handleCopy = async (kind: 'hex' | 'dump') => {
    if (!bytes) return;
    const text = kind === 'hex' ? toHexString(bytes) : toHexDump(bytes);
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus(kind === 'hex' ? 'hex-ok' : 'dump-ok');
    } catch {
      setCopyStatus('error');
    }
    scheduleCopyReset();
  };

  const handleDownloadPcap = () => {
    if (!bytes) return;
    const linkType = selectPcapLinkType(layers);
    const pcapBytes = buildPcap(bytes, { linkType, timestampMs: Date.now() });
    const blob = new Blob([pcapBytes.slice()], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'tsumiki-packet.pcap';
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Defer revoking the object URL so asynchronous download initiation succeeds across browsers
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const hoveredByteDetail = (() => {
    if (!isSuccess || !bytes || !highlight) return null;
    if (highlight.kind === 'layer') {
      const seg = segments.find(
        (s) => s.layerIndex === highlight.layerIndex && s.layerType !== 'payload',
      );
      if (!seg || seg.layerType === 'payload') return null;
      const meta = LAYER_META[seg.layerType];
      const endByte = seg.byteOffset + seg.byteLength - 1;
      const startBit = seg.byteOffset * 8;
      const endBit = (seg.byteOffset + seg.byteLength) * 8 - 1;
      return {
        title: `${meta.name} Header`,
        metrics: `${seg.byteLength} bytes (${seg.byteLength * 8} bits) · bytes ${seg.byteOffset}..${endByte} · bits ${startBit}..${endBit}`,
        fields: meta.rfc,
      };
    }
    if (highlight.kind === 'byte') {
      const value = bytes[highlight.byteIndex];
      if (value === undefined) return null;
      const byteStart = highlight.byteIndex * 8;
      const matching = spans.filter(
        (s) => s.bitOffset < byteStart + 8 && s.bitOffset + s.bitLength > byteStart,
      );
      return {
        title: `Byte 0x${highlight.byteIndex.toString(16).padStart(2, '0')} (#${highlight.byteIndex})`,
        metrics: `0x${value.toString(16).padStart(2, '0')} · dec ${value} · bin ${formatByteBinary(value)}`,
        fields: matching.map((s) => `${s.label} (${s.bitLength}b)`).join(' + '),
      };
    }
    const span = spans.find(
      (s) => s.layerIndex === highlight.layerIndex && s.fieldId === highlight.fieldId,
    );
    if (!span) return null;
    const startByte = Math.floor(span.bitOffset / 8);
    const endByte = Math.floor((span.bitOffset + span.bitLength - 1) / 8);
    const byteRange =
      startByte === endByte ? `byte ${startByte}` : `bytes ${startByte}..${endByte}`;
    return {
      title: span.label,
      metrics: `${span.bitLength} bits · ${byteRange} · packet bits ${span.bitOffset}..${span.bitOffset + span.bitLength - 1}`,
      fields: span.layerType === 'payload' ? 'Payload' : LAYER_META[span.layerType].name,
    };
  })();

  return (
    <aside className="inspector-panel" aria-label="Packet output inspector">
      <div className="inspector-header">
        <div>
          <h2 className="inspector-title">Packet Output (Hex Dump)</h2>
          <p className="inspector-subtitle">Network byte order (big-endian)</p>
        </div>
        <div className="inspector-badges">
          {isSuccess ? (
            <>
              <span className="status-badge is-size mono">{totalBytes} bytes</span>
              <span
                className={`status-badge ${warnings.length > 0 ? 'is-warning' : 'is-ok'}`}
              >
                {warnings.length > 0
                  ? `${warnings.length} ${warnings.length === 1 ? 'warning' : 'warnings'}`
                  : 'Valid'}
              </span>
            </>
          ) : (
            <span className="status-badge is-error">
              {errorCount} {errorCount === 1 ? 'error' : 'errors'}
            </span>
          )}
        </div>
      </div>

      <div className="export-toolbar" role="group" aria-label="Export packet">
        <button
          type="button"
          className="export-btn is-primary"
          disabled={!isSuccess || totalBytes === 0}
          onClick={() => void handleCopy('hex')}
        >
          {copyStatus === 'hex-ok' ? 'Copied Hex!' : 'Copy Hex'}
        </button>
        <button
          type="button"
          className="export-btn"
          disabled={!isSuccess || totalBytes === 0}
          onClick={() => void handleCopy('dump')}
        >
          {copyStatus === 'dump-ok' ? 'Copied Dump!' : 'Copy Dump'}
        </button>
        <button
          type="button"
          className="export-btn"
          disabled={!isSuccess || totalBytes === 0}
          onClick={handleDownloadPcap}
        >
          Download .pcap
        </button>
        {copyStatus === 'error' && (
          <span className="export-status-error" role="alert">
            Clipboard access denied
          </span>
        )}
      </div>

      {isSuccess && segments.length > 0 && (
        <div
          className="segment-overview"
          onMouseLeave={() => onHighlightChange(null)}
        >
          <div className="segment-bar" role="group" aria-label="Byte breakdown by layer">
            {segments.map((seg) => {
              const target: HighlightTarget =
                seg.layerType === 'payload'
                  ? { kind: 'field', layerIndex: seg.layerIndex, fieldId: 'payload' }
                  : { kind: 'layer', layerIndex: seg.layerIndex };
              return (
                <button
                  key={`${seg.layerIndex}-${seg.layerType}`}
                  type="button"
                  className={`segment-bar-slice layer-bg-${seg.layerType}`}
                  style={{ flexGrow: seg.byteLength }}
                  title={`${segmentFullLabel(seg.layerType)}: ${seg.byteLength} bytes (offset ${seg.byteOffset}..${seg.byteOffset + seg.byteLength - 1})`}
                  onClick={() => onHighlightChange(target)}
                  onMouseEnter={() => onHighlightChange(target)}
                  onMouseLeave={() => onHighlightChange(null)}
                  onFocus={() => onHighlightChange(target)}
                  onBlur={() => onHighlightChange(null)}
                >
                  <span>{segmentShortLabel(seg.layerType)}</span>
                </button>
              );
            })}
          </div>
          <div className="segment-legend" role="group" aria-label="Layer byte legend">
            {segments.map((seg) => {
              const target: HighlightTarget =
                seg.layerType === 'payload'
                  ? { kind: 'field', layerIndex: seg.layerIndex, fieldId: 'payload' }
                  : { kind: 'layer', layerIndex: seg.layerIndex };
              return (
                <button
                  key={`${seg.layerIndex}-${seg.layerType}`}
                  type="button"
                  className="legend-item"
                  onClick={() => onHighlightChange(target)}
                  onMouseEnter={() => onHighlightChange(target)}
                  onMouseLeave={() => onHighlightChange(null)}
                  onFocus={() => onHighlightChange(target)}
                  onBlur={() => onHighlightChange(null)}
                >
                  <span className={`legend-swatch layer-bg-${seg.layerType}`} />
                  <span>{segmentFullLabel(seg.layerType)}</span>
                  <span className="mono legend-bytes">{seg.byteLength}B</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {!isSuccess ? (
        <div className="inspector-error-box" role="alert">
          <p className="inspector-error-heading">
            Fix the input errors below to generate the packet bytes.
          </p>
          <ul className="inspector-msg-list">
            {payloadError && <li>Payload: {payloadError}</li>}
            {errors.map((err, i) => (
              <li key={i}>
                {err.layerIndex !== null ? `Layer #${err.layerIndex + 1}: ` : ''}
                {err.message}
              </li>
            ))}
          </ul>
        </div>
      ) : rows.length === 0 ? (
        <div className="hexdump-empty">
          Packet is empty (0 bytes). Add a header layer or enter a payload on the left.
        </div>
      ) : (
        <>
          <div className="hover-detail-strip mono" aria-live="polite">
            {hoveredByteDetail ? (
              <>
                <span className="hover-detail-title">{hoveredByteDetail.title}</span>
                <span className="hover-detail-metrics">{hoveredByteDetail.metrics}</span>
                {hoveredByteDetail.fields && (
                  <span className="hover-detail-fields">{hoveredByteDetail.fields}</span>
                )}
              </>
            ) : (
              <span className="hover-detail-placeholder">
                Hover a field, hex byte, header pill, or bit-diagram cell to inspect bit &amp; byte mapping.
              </span>
            )}
          </div>

          <div
            className="hexdump-box mono"
            role="region"
            aria-label="Hexadecimal dump"
            onMouseLeave={() => onHighlightChange(null)}
          >
            <div className="hexdump-grid">
              <div className="hexdump-head" aria-hidden="true">
                <span className="hexdump-offset-col">OFFSET</span>
                <span className="hexdump-bytes-col">
                  {HEX_COL_HEADERS.map((col, idx) => (
                    <span
                      key={col}
                      className={`hex-byte-head${idx === 7 ? ' is-mid-gap' : ''}`}
                    >
                      {col}
                    </span>
                  ))}
                </span>
                <span className="hexdump-ascii-col">ASCII</span>
              </div>
              <div className="hexdump-rows">
                {rows.map((row) => {
                  let mask = 0;
                  if (highlightedByteSet.size > 0) {
                    for (let idx = 0; idx < row.cells.length; idx++) {
                      if (highlightedByteSet.has(row.cells[idx].byteIndex)) {
                        mask |= 1 << idx;
                      }
                    }
                  }
                  return (
                    <HexDumpRowView
                      key={row.offset}
                      row={row}
                      highlightMask={mask}
                      onHoverByte={handleHoverByte}
                    />
                  );
                })}
              </div>
            </div>
          </div>

          <BitDiagram
            layers={layers}
            spans={spans}
            segments={segments}
            highlight={highlight}
            onHighlightChange={onHighlightChange}
          />
        </>
      )}

      {warnings.length > 0 && (
        <div className="inspector-warnings">
          <h3 className="inspector-warnings-title">
            Notes &amp; Warnings ({warnings.length})
          </h3>
          <ul className="inspector-msg-list">
            {warnings.map((w, i) => (
              <li key={i}>{w.message}</li>
            ))}
          </ul>
        </div>
      )}
    </aside>
  );
}
