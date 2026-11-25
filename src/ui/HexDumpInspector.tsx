import type { HexDumpRow, LayerSegmentSummary } from '../core/inspector';
import type { BuildPacketResult, LayerType } from '../core/layers/types';
import { LAYER_META } from './layerMeta';

export interface HexDumpInspectorProps {
  readonly buildResult: BuildPacketResult;
  readonly payloadError?: string;
  readonly rows: readonly HexDumpRow[];
  readonly segments: readonly LayerSegmentSummary[];
}

function segmentShortLabel(type: LayerType | 'payload'): string {
  return type === 'payload' ? 'DATA' : LAYER_META[type].shortName;
}

function segmentFullLabel(type: LayerType | 'payload'): string {
  return type === 'payload' ? 'Payload' : LAYER_META[type].name;
}

export function HexDumpInspector({
  buildResult,
  payloadError,
  rows,
  segments,
}: HexDumpInspectorProps) {
  const hasPayloadError = Boolean(payloadError);
  const isSuccess = buildResult.ok && !hasPayloadError;
  const totalBytes = isSuccess ? buildResult.bytes.length : 0;
  const warnings = buildResult.warnings;
  const errors = buildResult.ok ? [] : buildResult.errors;

  return (
    <aside className="inspector-panel" aria-label="組み立て結果インスペクタ">
      <div className="inspector-header">
        <div>
          <h2 className="inspector-title">パケット出力（16 進ダンプ）</h2>
          <p className="inspector-subtitle">ネットワークバイトオーダー（ビッグエンディアン）</p>
        </div>
        <div className="inspector-badges">
          {isSuccess ? (
            <>
              <span className="status-badge is-size mono">{totalBytes} bytes</span>
              <span
                className={`status-badge ${warnings.length > 0 ? 'is-warning' : 'is-ok'}`}
              >
                {warnings.length > 0 ? `警告 ${warnings.length} 件` : '正常'}
              </span>
            </>
          ) : (
            <span className="status-badge is-error">
              エラー {errors.length + (hasPayloadError ? 1 : 0)} 件
            </span>
          )}
        </div>
      </div>

      {isSuccess && segments.length > 0 && (
        <div className="segment-overview">
          <div className="segment-bar" aria-label="レイヤーごとのバイト構成">
            {segments.map((seg) => (
              <div
                key={`${seg.layerIndex}-${seg.layerType}`}
                className={`segment-bar-slice layer-bg-${seg.layerType}`}
                style={{ flexGrow: seg.byteLength }}
                title={`${segmentFullLabel(seg.layerType)}: ${seg.byteLength} バイト (offset ${seg.byteOffset}..${seg.byteOffset + seg.byteLength - 1})`}
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
            入力エラーを修正するとパケットのバイト列が生成されます。
          </p>
          <ul className="inspector-msg-list">
            {payloadError && <li>Payload: {payloadError}</li>}
            {errors.map((err, i) => (
              <li key={i}>
                {err.layerIndex !== null ? `レイヤー #${err.layerIndex + 1}: ` : ''}
                {err.message}
              </li>
            ))}
          </ul>
        </div>
      ) : rows.length === 0 ? (
        <div className="hexdump-empty">
          レイヤーもペイロードも空です（0 バイト）。左側からレイヤーを追加するかペイロードを入力してください。
        </div>
      ) : (
        <div className="hexdump-box mono" role="region" aria-label="16 進ダンプ">
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
                  {row.cells.map((cell, idx) => (
                    <span
                      key={cell.byteIndex}
                      className={`hex-byte${cell.layerType ? ` layer-fg-${cell.layerType}` : ''}${idx === 7 ? ' is-mid-gap' : ''}`}
                      title={
                        cell.spans.length > 0
                          ? `offset 0x${cell.byteIndex.toString(16).padStart(2, '0')} (${cell.byteIndex}): ${cell.spans.map((s) => s.label).join(' / ')}`
                          : `offset ${cell.byteIndex}`
                      }
                    >
                      {cell.hex}
                    </span>
                  ))}
                </span>
                <span className="hexdump-ascii-col">
                  {row.cells.map((cell) => (
                    <span
                      key={cell.byteIndex}
                      className={`ascii-char${cell.layerType ? ` layer-fg-${cell.layerType}` : ''}`}
                    >
                      {cell.ascii}
                    </span>
                  ))}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {warnings.length > 0 && (
        <div className="inspector-warnings">
          <h3 className="inspector-warnings-title">学習ヒント・警告（{warnings.length} 件）</h3>
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
