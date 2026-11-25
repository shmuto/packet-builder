import { useState } from 'react';
import type {
  Layer,
  PacketError,
  PacketWarning,
  TCPFlags,
} from '../core/layers/types';
import { AutoManualField, NumberField, TextField } from './FieldControls';
import { LAYER_META } from './layerMeta';

export interface LayerCardProps {
  readonly id: string;
  readonly index: number;
  readonly total: number;
  readonly layer: Layer;
  readonly resolvedAutoValues?: Readonly<Record<string, number>>;
  readonly errors: readonly PacketError[];
  readonly warnings: readonly PacketWarning[];
  readonly onChange: (next: Layer) => void;
  readonly onMoveUp: () => void;
  readonly onMoveDown: () => void;
  readonly onRemove: () => void;
}

const TCP_FLAG_ITEMS: readonly { readonly key: keyof TCPFlags; readonly label: string }[] = [
  { key: 'cwr', label: 'CWR' },
  { key: 'ece', label: 'ECE' },
  { key: 'urg', label: 'URG' },
  { key: 'ack', label: 'ACK' },
  { key: 'psh', label: 'PSH' },
  { key: 'rst', label: 'RST' },
  { key: 'syn', label: 'SYN' },
  { key: 'fin', label: 'FIN' },
];

export function LayerCard({
  id,
  index,
  total,
  layer,
  resolvedAutoValues,
  errors,
  warnings,
  onChange,
  onMoveUp,
  onMoveDown,
  onRemove,
}: LayerCardProps) {
  const [collapsed, setCollapsed] = useState(false);
  const meta = LAYER_META[layer.type];

  const fieldError = (fieldId: string) =>
    errors.find((e) => e.fieldId === fieldId)?.message;
  const fieldWarning = (fieldId: string) =>
    warnings.find((w) => w.fieldId === fieldId)?.message;

  const generalErrors = errors.filter((e) => e.fieldId === undefined);
  const generalWarnings = warnings.filter((w) => w.fieldId === undefined);
  const hasErrors = errors.length > 0;
  const hasWarnings = warnings.length > 0;

  return (
    <section
      className={`layer-card layer-theme-${layer.type}${hasErrors ? ' has-error' : ''}`}
      aria-label={`${meta.name} レイヤー`}
    >
      <header className="layer-header">
        <button
          type="button"
          className="layer-collapse-btn"
          aria-expanded={!collapsed}
          onClick={() => setCollapsed((c) => !c)}
        >
          <span className="layer-chevron" aria-hidden="true">
            {collapsed ? '▸' : '▾'}
          </span>
          <span className="layer-osi">{meta.osiLabel}</span>
          <span className="layer-name">{meta.name}</span>
          <span className="layer-rfc">{meta.rfc}</span>
          {hasErrors && <span className="layer-status-dot is-error" title="エラーあり" />}
          {!hasErrors && hasWarnings && (
            <span className="layer-status-dot is-warning" title="警告あり" />
          )}
        </button>

        <div className="layer-actions">
          <button
            type="button"
            className="icon-btn"
            aria-label={`${meta.name} を上へ移動`}
            disabled={index === 0}
            onClick={onMoveUp}
          >
            ↑
          </button>
          <button
            type="button"
            className="icon-btn"
            aria-label={`${meta.name} を下へ移動`}
            disabled={index === total - 1}
            onClick={onMoveDown}
          >
            ↓
          </button>
          <button
            type="button"
            className="icon-btn is-danger"
            aria-label={`${meta.name} を削除`}
            onClick={onRemove}
          >
            ✕
          </button>
        </div>
      </header>

      {!collapsed && (
        <div className="layer-body">
          {generalErrors.map((err, i) => (
            <div key={i} className="layer-banner is-error" role="alert">
              {err.message}
            </div>
          ))}
          {generalWarnings.map((warn, i) => (
            <div key={i} className="layer-banner is-warning">
              {warn.message}
            </div>
          ))}

          {layer.type === 'ethernet' && (
            <div className="field-grid">
              <TextField
                id={`${id}-dstMac`}
                label="宛先 MAC アドレス"
                hint="6 バイト"
                placeholder="00:11:22:33:44:55"
                value={layer.dstMac}
                error={fieldError('dstMac')}
                warning={fieldWarning('dstMac')}
                onChange={(dstMac) => onChange({ ...layer, dstMac })}
              />
              <TextField
                id={`${id}-srcMac`}
                label="送信元 MAC アドレス"
                hint="6 バイト"
                placeholder="66:77:88:99:aa:bb"
                value={layer.srcMac}
                error={fieldError('srcMac')}
                warning={fieldWarning('srcMac')}
                onChange={(srcMac) => onChange({ ...layer, srcMac })}
              />
              <AutoManualField
                id={`${id}-etherType`}
                label="EtherType"
                hint="0x0800 = IPv4"
                allowHex
                hexDigits={4}
                value={layer.etherType}
                resolvedAutoValue={resolvedAutoValues?.etherType}
                error={fieldError('etherType')}
                warning={fieldWarning('etherType')}
                onChange={(etherType) => onChange({ ...layer, etherType })}
              />
            </div>
          )}

          {layer.type === 'ipv4' && (
            <div className="field-grid">
              <TextField
                id={`${id}-srcIp`}
                label="送信元 IPv4 アドレス"
                hint="32 bit"
                placeholder="192.168.0.1"
                value={layer.srcIp}
                error={fieldError('srcIp')}
                warning={fieldWarning('srcIp')}
                onChange={(srcIp) => onChange({ ...layer, srcIp })}
              />
              <TextField
                id={`${id}-dstIp`}
                label="宛先 IPv4 アドレス"
                hint="32 bit"
                placeholder="192.168.0.2"
                value={layer.dstIp}
                error={fieldError('dstIp')}
                warning={fieldWarning('dstIp')}
                onChange={(dstIp) => onChange({ ...layer, dstIp })}
              />
              <NumberField
                id={`${id}-ttl`}
                label="TTL"
                hint="0〜255"
                value={layer.ttl}
                error={fieldError('ttl')}
                warning={fieldWarning('ttl')}
                onChange={(ttl) => onChange({ ...layer, ttl })}
              />
              <NumberField
                id={`${id}-identification`}
                label="Identification"
                hint="0x0000〜0xffff"
                allowHex
                hexDigits={4}
                value={layer.identification}
                error={fieldError('identification')}
                warning={fieldWarning('identification')}
                onChange={(identification) => onChange({ ...layer, identification })}
              />
              <NumberField
                id={`${id}-tos`}
                label="TOS (DSCP/ECN)"
                hint="0〜255"
                allowHex
                hexDigits={2}
                value={layer.tos}
                error={fieldError('tos')}
                warning={fieldWarning('tos')}
                onChange={(tos) => onChange({ ...layer, tos })}
              />
              <NumberField
                id={`${id}-fragmentOffset`}
                label="Fragment Offset"
                hint="0〜8191 (13 bit)"
                value={layer.fragmentOffset}
                error={fieldError('fragmentOffset')}
                warning={fieldWarning('fragmentOffset')}
                onChange={(fragmentOffset) => onChange({ ...layer, fragmentOffset })}
              />

              <div className="field field-span-full">
                <div className="field-label-row">
                  <span className="field-label">Flags（3 bit）</span>
                  <span className="field-hint">Version=4 / IHL=5 固定</span>
                </div>
                <div className="flag-chip-row">
                  <label className={`flag-chip${layer.flags.reserved ? ' is-checked' : ''}`}>
                    <input
                      type="checkbox"
                      checked={layer.flags.reserved}
                      onChange={(e) =>
                        onChange({
                          ...layer,
                          flags: { ...layer.flags, reserved: e.target.checked },
                        })
                      }
                    />
                    <span>Reserved</span>
                  </label>
                  <label className={`flag-chip${layer.flags.df ? ' is-checked' : ''}`}>
                    <input
                      type="checkbox"
                      checked={layer.flags.df}
                      onChange={(e) =>
                        onChange({
                          ...layer,
                          flags: { ...layer.flags, df: e.target.checked },
                        })
                      }
                    />
                    <span>DF (Don&apos;t Fragment)</span>
                  </label>
                  <label className={`flag-chip${layer.flags.mf ? ' is-checked' : ''}`}>
                    <input
                      type="checkbox"
                      checked={layer.flags.mf}
                      onChange={(e) =>
                        onChange({
                          ...layer,
                          flags: { ...layer.flags, mf: e.target.checked },
                        })
                      }
                    />
                    <span>MF (More Fragments)</span>
                  </label>
                </div>
                {fieldWarning('flags') && (
                  <p className="field-msg is-warning">{fieldWarning('flags')}</p>
                )}
              </div>

              <AutoManualField
                id={`${id}-totalLength`}
                label="Total Length"
                hint="バイト"
                value={layer.totalLength}
                resolvedAutoValue={resolvedAutoValues?.totalLength}
                error={fieldError('totalLength')}
                warning={fieldWarning('totalLength')}
                onChange={(totalLength) => onChange({ ...layer, totalLength })}
              />
              <AutoManualField
                id={`${id}-protocol`}
                label="Protocol"
                hint="1=ICMP / 6=TCP / 17=UDP"
                value={layer.protocol}
                resolvedAutoValue={resolvedAutoValues?.protocol}
                error={fieldError('protocol')}
                warning={fieldWarning('protocol')}
                onChange={(protocol) => onChange({ ...layer, protocol })}
              />
              <AutoManualField
                id={`${id}-headerChecksum`}
                label="Header Checksum"
                hint="RFC 1071"
                allowHex
                hexDigits={4}
                value={layer.headerChecksum}
                resolvedAutoValue={resolvedAutoValues?.headerChecksum}
                error={fieldError('headerChecksum')}
                warning={fieldWarning('headerChecksum')}
                onChange={(headerChecksum) => onChange({ ...layer, headerChecksum })}
              />
            </div>
          )}

          {layer.type === 'icmp' && (
            <div className="field-grid">
              <NumberField
                id={`${id}-icmpType`}
                label="Type"
                hint="8=Echo Req / 0=Reply"
                value={layer.icmpType}
                error={fieldError('icmpType')}
                warning={fieldWarning('icmpType')}
                onChange={(icmpType) => onChange({ ...layer, icmpType })}
              />
              <NumberField
                id={`${id}-code`}
                label="Code"
                hint="0〜255"
                value={layer.code}
                error={fieldError('code')}
                warning={fieldWarning('code')}
                onChange={(code) => onChange({ ...layer, code })}
              />
              <NumberField
                id={`${id}-identifier`}
                label="Identifier"
                hint="0〜65535"
                value={layer.identifier}
                error={fieldError('identifier')}
                warning={fieldWarning('identifier')}
                onChange={(identifier) => onChange({ ...layer, identifier })}
              />
              <NumberField
                id={`${id}-sequenceNumber`}
                label="Sequence Number"
                hint="0〜65535"
                value={layer.sequenceNumber}
                error={fieldError('sequenceNumber')}
                warning={fieldWarning('sequenceNumber')}
                onChange={(sequenceNumber) => onChange({ ...layer, sequenceNumber })}
              />
              <AutoManualField
                id={`${id}-checksum`}
                label="Checksum"
                hint="RFC 792"
                allowHex
                hexDigits={4}
                value={layer.checksum}
                resolvedAutoValue={resolvedAutoValues?.checksum}
                error={fieldError('checksum')}
                warning={fieldWarning('checksum')}
                onChange={(checksum) => onChange({ ...layer, checksum })}
              />
            </div>
          )}

          {layer.type === 'udp' && (
            <div className="field-grid">
              <NumberField
                id={`${id}-srcPort`}
                label="送信元ポート"
                hint="0〜65535"
                value={layer.srcPort}
                error={fieldError('srcPort')}
                warning={fieldWarning('srcPort')}
                onChange={(srcPort) => onChange({ ...layer, srcPort })}
              />
              <NumberField
                id={`${id}-dstPort`}
                label="宛先ポート"
                hint="0〜65535"
                value={layer.dstPort}
                error={fieldError('dstPort')}
                warning={fieldWarning('dstPort')}
                onChange={(dstPort) => onChange({ ...layer, dstPort })}
              />
              <AutoManualField
                id={`${id}-length`}
                label="Length"
                hint="8 + ペイロード長"
                value={layer.length}
                resolvedAutoValue={resolvedAutoValues?.length}
                error={fieldError('length')}
                warning={fieldWarning('length')}
                onChange={(length) => onChange({ ...layer, length })}
              />
              <AutoManualField
                id={`${id}-checksum`}
                label="Checksum"
                hint="IPv4 擬似ヘッダ含む"
                allowHex
                hexDigits={4}
                value={layer.checksum}
                resolvedAutoValue={resolvedAutoValues?.checksum}
                error={fieldError('checksum')}
                warning={fieldWarning('checksum')}
                onChange={(checksum) => onChange({ ...layer, checksum })}
              />
            </div>
          )}

          {layer.type === 'tcp' && (
            <div className="field-grid">
              <NumberField
                id={`${id}-srcPort`}
                label="送信元ポート"
                hint="0〜65535"
                value={layer.srcPort}
                error={fieldError('srcPort')}
                warning={fieldWarning('srcPort')}
                onChange={(srcPort) => onChange({ ...layer, srcPort })}
              />
              <NumberField
                id={`${id}-dstPort`}
                label="宛先ポート"
                hint="0〜65535"
                value={layer.dstPort}
                error={fieldError('dstPort')}
                warning={fieldWarning('dstPort')}
                onChange={(dstPort) => onChange({ ...layer, dstPort })}
              />
              <NumberField
                id={`${id}-seqNumber`}
                label="Sequence Number"
                hint="32 bit"
                value={layer.seqNumber}
                error={fieldError('seqNumber')}
                warning={fieldWarning('seqNumber')}
                onChange={(seqNumber) => onChange({ ...layer, seqNumber })}
              />
              <NumberField
                id={`${id}-ackNumber`}
                label="Acknowledgment Number"
                hint="32 bit"
                value={layer.ackNumber}
                error={fieldError('ackNumber')}
                warning={fieldWarning('ackNumber')}
                onChange={(ackNumber) => onChange({ ...layer, ackNumber })}
              />
              <NumberField
                id={`${id}-windowSize`}
                label="Window Size"
                hint="0〜65535"
                value={layer.windowSize}
                error={fieldError('windowSize')}
                warning={fieldWarning('windowSize')}
                onChange={(windowSize) => onChange({ ...layer, windowSize })}
              />
              <NumberField
                id={`${id}-urgentPointer`}
                label="Urgent Pointer"
                hint="0〜65535"
                value={layer.urgentPointer}
                error={fieldError('urgentPointer')}
                warning={fieldWarning('urgentPointer')}
                onChange={(urgentPointer) => onChange({ ...layer, urgentPointer })}
              />

              <div className="field field-span-full">
                <div className="field-label-row">
                  <span className="field-label">Control Bits（8 bit）</span>
                  <span className="field-hint">RFC 9293 Section 3.1</span>
                </div>
                <div className="flag-chip-row">
                  {TCP_FLAG_ITEMS.map(({ key, label }) => (
                    <label
                      key={key}
                      className={`flag-chip${layer.flags[key] ? ' is-checked' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={layer.flags[key]}
                        onChange={(e) =>
                          onChange({
                            ...layer,
                            flags: { ...layer.flags, [key]: e.target.checked },
                          })
                        }
                      />
                      <span>{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <AutoManualField
                id={`${id}-dataOffset`}
                label="Data Offset"
                hint="4 bit (基本=5)"
                value={layer.dataOffset}
                resolvedAutoValue={resolvedAutoValues?.dataOffset}
                error={fieldError('dataOffset')}
                warning={fieldWarning('dataOffset')}
                onChange={(dataOffset) => onChange({ ...layer, dataOffset })}
              />
              <AutoManualField
                id={`${id}-checksum`}
                label="Checksum"
                hint="IPv4 擬似ヘッダ含む"
                allowHex
                hexDigits={4}
                value={layer.checksum}
                resolvedAutoValue={resolvedAutoValues?.checksum}
                error={fieldError('checksum')}
                warning={fieldWarning('checksum')}
                onChange={(checksum) => onChange({ ...layer, checksum })}
              />
            </div>
          )}
        </div>
      )}
    </section>
  );
}
