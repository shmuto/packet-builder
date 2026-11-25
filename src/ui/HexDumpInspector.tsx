import { useEffect, useRef, useState } from 'react';
import { toHexDump, toHexString } from '../core/bytes';
import {
  formatByteBinary,
  isByteHighlighted,
  type EvaluatedPacketDraft,
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

function segmentShortLabel(type: LayerType | 'payload'): string {
  return type === 'payload' ? 'DATA' : LAYER_META[type].shortName;
}

function segmentFullLabel(type: LayerType | 'payload'): string {
  return type === 'payload' ? 'Payload' : LAYER_META[type].name;
}

export function HexDumpInspector({
  layers,
  draft,
  highlight,
  onHighlightChange,
}: HexDumpInspectorProps) {
  const { ok: isSuccess, bytes, spans, rows, segments, errors, warnings, payloadError } = draft;
  const totalBytes = bytes ? bytes.length : 0;
  const errorCount = errors.length + (payloadError ? 1 : 0);

  const [selectedDiagramLayer, setSelectedDiagramLayer] = useState(0);
  const [copyStatus, setCopyStatus] = useState<CopyStatus>('idle');
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  // Follow hovered layer automatically in the 32-bit diagram
  useEffect(() => {
    if (!highlight) return;
    if (highlight.kind === 'field') {
      if (highlight.layerIndex >= 0 && highlight.layerIndex < layers.length) {
        setSelectedDiagramLayer(highlight.layerIndex);
      }
      return;
    }
    const byteStart = highlight.byteIndex * 8;
    const match = spans.find(
      (s) => s.section === 'layer' && s.bitOffset < byteStart + 8 && s.bitOffset + s.bitLength > byteStart,
    );
    if (match) {
      setSelectedDiagramLayer(match.layerIndex);
    }
  }, [highlight, layers.length, spans]);

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
    URL.revokeObjectURL(url);
  };

  // Compute live detail strip for the active hover target
  const hoveredByteDetail = (() => {
    if (!isSuccess || !bytes || !highlight) return null;
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
        <div className="segment-overview">
          <div className="segment-bar" aria-label="Byte breakdown by layer">
            {segments.map((seg) => (
              <div
                key={`${seg.layerIndex}-${seg.layerType}`}
                className={`segment-bar-slice layer-bg-${seg.layerType}`}
                style={{ flexGrow: seg.byteLength }}
                title={`${segmentFullLabel(seg.layerType)}: ${seg.byteLength} bytes (offset ${seg.byteOffset}..${seg.byteOffset + seg.byteLength - 1})`}
              >
                <span>{segmentShortLabel(seg.layerType)}</span>
              </div>
            ))}
          </div>
          <div className="segment-legend">
            {segments.map((seg) => (
              <span
                key={`${seg.layerIndex}-${seg.layerType}`}
                className="legend-item"
              >
                <span className={`legend-swatch layer-bg-${seg.layerType}`} />
                <span>{segmentFullLabel(seg.layerType)}</span>
                <span className="mono legend-bytes">{seg.byteLength}B</span>
              </span>
            ))}
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
                Hover a field, hex byte, or bit-diagram cell to inspect bit &amp; byte mapping.
              </span>
            )}
          </div>

          <div
            className="hexdump-box mono"
            role="region"
            aria-label="Hexadecimal dump"
            onMouseLeave={() => onHighlightChange(null)}
          >
            <div className="hexdump-head" aria-hidden="true">
              <span className="hexdump-offset-col">OFFSET</span>
              <span className="hexdump-bytes-col">
                00 01 02 03 04 05 06 07 &nbsp;08 09 0a 0b 0c 0d 0e 0f
              </span>
              <span className="hexdump-ascii-col">ASCII</span>
            </div>
            <div className="hexdump-rows">
              {rows.map((row) => (
                <div key={row.offset} className="hexdump-row">
                  <span className="hexdump-offset-col">{row.offsetLabel}:</span>
                  <span className="hexdump-bytes-col">
                    {row.cells.map((cell, idx) => {
                      const highlighted = isByteHighlighted(cell, highlight);
                      return (
                        <span
                          key={cell.byteIndex}
                          className={`hex-byte${cell.layerType ? ` layer-fg-${cell.layerType}` : ''}${idx === 7 ? ' is-mid-gap' : ''}${highlighted ? ' is-highlighted' : ''}`}
                          onMouseEnter={() =>
                            onHighlightChange({ kind: 'byte', byteIndex: cell.byteIndex })
                          }
                        >
                          {cell.hex}
                        </span>
                      );
                    })}
                  </span>
                  <span className="hexdump-ascii-col">
                    {row.cells.map((cell) => {
                      const highlighted = isByteHighlighted(cell, highlight);
                      return (
                        <span
                          key={cell.byteIndex}
                          className={`ascii-char${cell.layerType ? ` layer-fg-${cell.layerType}` : ''}${highlighted ? ' is-highlighted' : ''}`}
                          onMouseEnter={() =>
                            onHighlightChange({ kind: 'byte', byteIndex: cell.byteIndex })
                          }
                        >
                          {cell.ascii}
                        </span>
                      );
                    })}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <BitDiagram
            layers={layers}
            spans={spans}
            selectedLayerIndex={selectedDiagramLayer}
            highlight={highlight}
            onSelectLayer={setSelectedDiagramLayer}
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
