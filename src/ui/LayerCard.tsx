import { useState } from 'react';
import {
  isFieldHighlighted,
  resolveHighlightedLayerIndex,
  type HighlightTarget,
} from '../core/inspector';
import { BGP_DEFAULT_MARKER_HEX } from '../core/layers/bgp';
import type {
  BGPMessageType,
  FieldSpan,
  Layer,
  PacketError,
  PacketWarning,
  TCPFlags,
} from '../core/layers/types';
import {
  AutoManualField,
  AutoManualTextField,
  FixedFieldChip,
  NumberField,
  TextField,
} from './FieldControls';
import { LAYER_META } from './layerMeta';

export interface LayerCardProps {
  readonly id: string;
  readonly index: number;
  readonly total: number;
  readonly layer: Layer;
  readonly spans: readonly FieldSpan[];
  readonly highlight: HighlightTarget | null;
  readonly resolvedAutoValues?: Readonly<Record<string, number>>;
  readonly errors: readonly PacketError[];
  readonly warnings: readonly PacketWarning[];
  readonly onHighlightChange: (target: HighlightTarget | null) => void;
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

const BGP_TYPE_OPTIONS: readonly { readonly type: BGPMessageType; readonly label: string }[] = [
  { type: 1, label: '1: OPEN' },
  { type: 2, label: '2: UPDATE' },
  { type: 3, label: '3: NOTIFICATION' },
  { type: 4, label: '4: KEEPALIVE' },
];

export function LayerCard({
  id,
  index,
  total,
  layer,
  spans,
  highlight,
  resolvedAutoValues,
  errors,
  warnings,
  onHighlightChange,
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

  const isHighlighted = (fieldId: string) =>
    isFieldHighlighted(index, fieldId, spans, highlight);
  const hoverStart = (fieldId: string) => () =>
    onHighlightChange({ kind: 'field', layerIndex: index, fieldId });
  const hoverEnd = () => onHighlightChange(null);

  const generalErrors = errors.filter((e) => e.fieldId === undefined);
  const generalWarnings = warnings.filter((w) => w.fieldId === undefined);
  const hasErrors = errors.length > 0;
  const hasWarnings = warnings.length > 0;
  const isLayerHighlighted = resolveHighlightedLayerIndex(spans, highlight) === index;

  return (
    <section
      className={`layer-card layer-theme-${layer.type}${hasErrors ? ' has-error' : ''}${isLayerHighlighted ? ' is-layer-highlighted' : ''}`}
      aria-label={`${meta.name} layer`}
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
          {hasErrors && <span className="layer-status-dot is-error" title="Has errors" />}
          {!hasErrors && hasWarnings && (
            <span className="layer-status-dot is-warning" title="Has warnings" />
          )}
        </button>

        <div className="layer-actions">
          <button
            type="button"
            className="icon-btn"
            aria-label={`Move ${meta.name} up`}
            disabled={index === 0}
            onClick={onMoveUp}
          >
            ↑
          </button>
          <button
            type="button"
            className="icon-btn"
            aria-label={`Move ${meta.name} down`}
            disabled={index === total - 1}
            onClick={onMoveDown}
          >
            ↓
          </button>
          <button
            type="button"
            className="icon-btn is-danger"
            aria-label={`Remove ${meta.name}`}
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
                label="Destination MAC"
                hint="48 bit"
                placeholder="00:11:22:33:44:55"
                value={layer.dstMac}
                error={fieldError('dstMac')}
                warning={fieldWarning('dstMac')}
                isHighlighted={isHighlighted('dstMac')}
                onHoverStart={hoverStart('dstMac')}
                onHoverEnd={hoverEnd}
                onChange={(dstMac) => onChange({ ...layer, dstMac })}
              />
              <TextField
                id={`${id}-srcMac`}
                label="Source MAC"
                hint="48 bit"
                placeholder="66:77:88:99:aa:bb"
                value={layer.srcMac}
                error={fieldError('srcMac')}
                warning={fieldWarning('srcMac')}
                isHighlighted={isHighlighted('srcMac')}
                onHoverStart={hoverStart('srcMac')}
                onHoverEnd={hoverEnd}
                onChange={(srcMac) => onChange({ ...layer, srcMac })}
              />
              <AutoManualField
                id={`${id}-etherType`}
                label="EtherType"
                hint="0x0800=IPv4 / 0x0806=ARP"
                allowHex
                hexDigits={4}
                value={layer.etherType}
                resolvedAutoValue={resolvedAutoValues?.etherType}
                error={fieldError('etherType')}
                warning={fieldWarning('etherType')}
                isHighlighted={isHighlighted('etherType')}
                onHoverStart={hoverStart('etherType')}
                onHoverEnd={hoverEnd}
                onChange={(etherType) => onChange({ ...layer, etherType })}
              />
            </div>
          )}

          {layer.type === 'arp' && (
            <div className="field-grid">
              <NumberField
                id={`${id}-operation`}
                label="Operation"
                hint="1=Request / 2=Reply"
                value={layer.operation}
                error={fieldError('operation')}
                warning={fieldWarning('operation')}
                isHighlighted={isHighlighted('operation')}
                onHoverStart={hoverStart('operation')}
                onHoverEnd={hoverEnd}
                onChange={(operation) => onChange({ ...layer, operation })}
              />
              <div className="field">
                <div className="field-label-row">
                  <span className="field-label">Quick Operation</span>
                  <span className="field-hint">RFC 826</span>
                </div>
                <div className="flag-chip-row">
                  <button
                    type="button"
                    className={`preset-btn${layer.operation === 1 ? ' is-active' : ''}`}
                    onClick={() => onChange({ ...layer, operation: 1 })}
                  >
                    1: Request
                  </button>
                  <button
                    type="button"
                    className={`preset-btn${layer.operation === 2 ? ' is-active' : ''}`}
                    onClick={() => onChange({ ...layer, operation: 2 })}
                  >
                    2: Reply
                  </button>
                </div>
              </div>
              <TextField
                id={`${id}-senderMac`}
                label="Sender MAC (SHA)"
                hint="48 bit"
                placeholder="66:77:88:99:aa:bb"
                value={layer.senderMac}
                error={fieldError('senderMac')}
                warning={fieldWarning('senderMac')}
                isHighlighted={isHighlighted('senderMac')}
                onHoverStart={hoverStart('senderMac')}
                onHoverEnd={hoverEnd}
                onChange={(senderMac) => onChange({ ...layer, senderMac })}
              />
              <TextField
                id={`${id}-senderIp`}
                label="Sender IPv4 (SPA)"
                hint="32 bit"
                placeholder="192.168.0.1"
                value={layer.senderIp}
                error={fieldError('senderIp')}
                warning={fieldWarning('senderIp')}
                isHighlighted={isHighlighted('senderIp')}
                onHoverStart={hoverStart('senderIp')}
                onHoverEnd={hoverEnd}
                onChange={(senderIp) => onChange({ ...layer, senderIp })}
              />
              <TextField
                id={`${id}-targetMac`}
                label="Target MAC (THA)"
                hint="48 bit"
                placeholder="00:00:00:00:00:00"
                value={layer.targetMac}
                error={fieldError('targetMac')}
                warning={fieldWarning('targetMac')}
                isHighlighted={isHighlighted('targetMac')}
                onHoverStart={hoverStart('targetMac')}
                onHoverEnd={hoverEnd}
                onChange={(targetMac) => onChange({ ...layer, targetMac })}
              />
              <TextField
                id={`${id}-targetIp`}
                label="Target IPv4 (TPA)"
                hint="32 bit"
                placeholder="192.168.0.2"
                value={layer.targetIp}
                error={fieldError('targetIp')}
                warning={fieldWarning('targetIp')}
                isHighlighted={isHighlighted('targetIp')}
                onHoverStart={hoverStart('targetIp')}
                onHoverEnd={hoverEnd}
                onChange={(targetIp) => onChange({ ...layer, targetIp })}
              />
              <AutoManualField
                id={`${id}-hardwareType`}
                label="Hardware Type (HTYPE)"
                hint="1 = Ethernet"
                value={layer.hardwareType}
                resolvedAutoValue={resolvedAutoValues?.hardwareType}
                error={fieldError('hardwareType')}
                warning={fieldWarning('hardwareType')}
                isHighlighted={isHighlighted('hardwareType')}
                onHoverStart={hoverStart('hardwareType')}
                onHoverEnd={hoverEnd}
                onChange={(hardwareType) => onChange({ ...layer, hardwareType })}
              />
              <AutoManualField
                id={`${id}-protocolType`}
                label="Protocol Type (PTYPE)"
                hint="0x0800 = IPv4"
                allowHex
                hexDigits={4}
                value={layer.protocolType}
                resolvedAutoValue={resolvedAutoValues?.protocolType}
                error={fieldError('protocolType')}
                warning={fieldWarning('protocolType')}
                isHighlighted={isHighlighted('protocolType')}
                onHoverStart={hoverStart('protocolType')}
                onHoverEnd={hoverEnd}
                onChange={(protocolType) => onChange({ ...layer, protocolType })}
              />
              <AutoManualField
                id={`${id}-hardwareLength`}
                label="Hardware Size (HLEN)"
                hint="6 bytes"
                value={layer.hardwareLength}
                resolvedAutoValue={resolvedAutoValues?.hardwareLength}
                error={fieldError('hardwareLength')}
                warning={fieldWarning('hardwareLength')}
                isHighlighted={isHighlighted('hardwareLength')}
                onHoverStart={hoverStart('hardwareLength')}
                onHoverEnd={hoverEnd}
                onChange={(hardwareLength) => onChange({ ...layer, hardwareLength })}
              />
              <AutoManualField
                id={`${id}-protocolLength`}
                label="Protocol Size (PLEN)"
                hint="4 bytes"
                value={layer.protocolLength}
                resolvedAutoValue={resolvedAutoValues?.protocolLength}
                error={fieldError('protocolLength')}
                warning={fieldWarning('protocolLength')}
                isHighlighted={isHighlighted('protocolLength')}
                onHoverStart={hoverStart('protocolLength')}
                onHoverEnd={hoverEnd}
                onChange={(protocolLength) => onChange({ ...layer, protocolLength })}
              />
            </div>
          )}

          {layer.type === 'ipv4' && (
            <div className="field-grid">
              <div className="fixed-field-row field-span-full">
                <FixedFieldChip
                  label="Version"
                  value="4"
                  bits="4b"
                  isHighlighted={isHighlighted('version')}
                  onHoverStart={hoverStart('version')}
                  onHoverEnd={hoverEnd}
                />
                <FixedFieldChip
                  label="IHL"
                  value="5 (20B)"
                  bits="4b"
                  isHighlighted={isHighlighted('ihl')}
                  onHoverStart={hoverStart('ihl')}
                  onHoverEnd={hoverEnd}
                />
              </div>

              <TextField
                id={`${id}-srcIp`}
                label="Source IPv4"
                hint="32 bit"
                placeholder="192.168.0.1"
                value={layer.srcIp}
                error={fieldError('srcIp')}
                warning={fieldWarning('srcIp')}
                isHighlighted={isHighlighted('srcIp')}
                onHoverStart={hoverStart('srcIp')}
                onHoverEnd={hoverEnd}
                onChange={(srcIp) => onChange({ ...layer, srcIp })}
              />
              <TextField
                id={`${id}-dstIp`}
                label="Destination IPv4"
                hint="32 bit"
                placeholder="192.168.0.2"
                value={layer.dstIp}
                error={fieldError('dstIp')}
                warning={fieldWarning('dstIp')}
                isHighlighted={isHighlighted('dstIp')}
                onHoverStart={hoverStart('dstIp')}
                onHoverEnd={hoverEnd}
                onChange={(dstIp) => onChange({ ...layer, dstIp })}
              />
              <NumberField
                id={`${id}-ttl`}
                label="TTL"
                hint="0-255"
                value={layer.ttl}
                error={fieldError('ttl')}
                warning={fieldWarning('ttl')}
                isHighlighted={isHighlighted('ttl')}
                onHoverStart={hoverStart('ttl')}
                onHoverEnd={hoverEnd}
                onChange={(ttl) => onChange({ ...layer, ttl })}
              />
              <NumberField
                id={`${id}-identification`}
                label="Identification"
                hint="0x0000-0xffff"
                allowHex
                hexDigits={4}
                value={layer.identification}
                error={fieldError('identification')}
                warning={fieldWarning('identification')}
                isHighlighted={isHighlighted('identification')}
                onHoverStart={hoverStart('identification')}
                onHoverEnd={hoverEnd}
                onChange={(identification) => onChange({ ...layer, identification })}
              />
              <NumberField
                id={`${id}-tos`}
                label="TOS (DSCP/ECN)"
                hint="8 bit"
                allowHex
                hexDigits={2}
                value={layer.tos}
                error={fieldError('tos')}
                warning={fieldWarning('tos')}
                isHighlighted={isHighlighted('tos')}
                onHoverStart={hoverStart('tos')}
                onHoverEnd={hoverEnd}
                onChange={(tos) => onChange({ ...layer, tos })}
              />
              <NumberField
                id={`${id}-fragmentOffset`}
                label="Fragment Offset"
                hint="0-8191 (13 bit)"
                value={layer.fragmentOffset}
                error={fieldError('fragmentOffset')}
                warning={fieldWarning('fragmentOffset')}
                isHighlighted={isHighlighted('fragmentOffset')}
                onHoverStart={hoverStart('fragmentOffset')}
                onHoverEnd={hoverEnd}
                onChange={(fragmentOffset) => onChange({ ...layer, fragmentOffset })}
              />

              <div
                className={`field field-span-full${isHighlighted('flags') ? ' is-highlighted' : ''}`}
                onMouseEnter={hoverStart('flags')}
                onMouseLeave={hoverEnd}
              >
                <div className="field-label-row">
                  <span className="field-label">Flags</span>
                  <span className="field-hint">3 bit (R / DF / MF)</span>
                </div>
                <div className="flag-chip-row">
                  <label className={`flag-chip${layer.flags.reserved ? ' is-checked' : ''}`}>
                    <input
                      type="checkbox"
                      checked={layer.flags.reserved}
                      onFocus={hoverStart('flags')}
                      onBlur={hoverEnd}
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
                      onFocus={hoverStart('flags')}
                      onBlur={hoverEnd}
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
                      onFocus={hoverStart('flags')}
                      onBlur={hoverEnd}
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
                hint="bytes"
                value={layer.totalLength}
                resolvedAutoValue={resolvedAutoValues?.totalLength}
                error={fieldError('totalLength')}
                warning={fieldWarning('totalLength')}
                isHighlighted={isHighlighted('totalLength')}
                onHoverStart={hoverStart('totalLength')}
                onHoverEnd={hoverEnd}
                onChange={(totalLength) => onChange({ ...layer, totalLength })}
              />
              <AutoManualField
                id={`${id}-protocol`}
                label="Protocol"
                hint="1=ICMP / 4=IP-in-IP / 6=TCP / 17=UDP"
                value={layer.protocol}
                resolvedAutoValue={resolvedAutoValues?.protocol}
                error={fieldError('protocol')}
                warning={fieldWarning('protocol')}
                isHighlighted={isHighlighted('protocol')}
                onHoverStart={hoverStart('protocol')}
                onHoverEnd={hoverEnd}
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
                isHighlighted={isHighlighted('headerChecksum')}
                onHoverStart={hoverStart('headerChecksum')}
                onHoverEnd={hoverEnd}
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
                isHighlighted={isHighlighted('icmpType')}
                onHoverStart={hoverStart('icmpType')}
                onHoverEnd={hoverEnd}
                onChange={(icmpType) => onChange({ ...layer, icmpType })}
              />
              <NumberField
                id={`${id}-code`}
                label="Code"
                hint="0-255"
                value={layer.code}
                error={fieldError('code')}
                warning={fieldWarning('code')}
                isHighlighted={isHighlighted('code')}
                onHoverStart={hoverStart('code')}
                onHoverEnd={hoverEnd}
                onChange={(code) => onChange({ ...layer, code })}
              />
              <NumberField
                id={`${id}-identifier`}
                label="Identifier"
                hint="0-65535"
                value={layer.identifier}
                error={fieldError('identifier')}
                warning={fieldWarning('identifier')}
                isHighlighted={isHighlighted('identifier')}
                onHoverStart={hoverStart('identifier')}
                onHoverEnd={hoverEnd}
                onChange={(identifier) => onChange({ ...layer, identifier })}
              />
              <NumberField
                id={`${id}-sequenceNumber`}
                label="Sequence Number"
                hint="0-65535"
                value={layer.sequenceNumber}
                error={fieldError('sequenceNumber')}
                warning={fieldWarning('sequenceNumber')}
                isHighlighted={isHighlighted('sequenceNumber')}
                onHoverStart={hoverStart('sequenceNumber')}
                onHoverEnd={hoverEnd}
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
                isHighlighted={isHighlighted('checksum')}
                onHoverStart={hoverStart('checksum')}
                onHoverEnd={hoverEnd}
                onChange={(checksum) => onChange({ ...layer, checksum })}
              />
            </div>
          )}

          {layer.type === 'udp' && (
            <div className="field-grid">
              <NumberField
                id={`${id}-srcPort`}
                label="Source Port"
                hint="0-65535"
                value={layer.srcPort}
                error={fieldError('srcPort')}
                warning={fieldWarning('srcPort')}
                isHighlighted={isHighlighted('srcPort')}
                onHoverStart={hoverStart('srcPort')}
                onHoverEnd={hoverEnd}
                onChange={(srcPort) => onChange({ ...layer, srcPort })}
              />
              <NumberField
                id={`${id}-dstPort`}
                label="Destination Port"
                hint="0-65535"
                value={layer.dstPort}
                error={fieldError('dstPort')}
                warning={fieldWarning('dstPort')}
                isHighlighted={isHighlighted('dstPort')}
                onHoverStart={hoverStart('dstPort')}
                onHoverEnd={hoverEnd}
                onChange={(dstPort) => onChange({ ...layer, dstPort })}
              />
              <AutoManualField
                id={`${id}-length`}
                label="Length"
                hint="8 + payload"
                value={layer.length}
                resolvedAutoValue={resolvedAutoValues?.length}
                error={fieldError('length')}
                warning={fieldWarning('length')}
                isHighlighted={isHighlighted('length')}
                onHoverStart={hoverStart('length')}
                onHoverEnd={hoverEnd}
                onChange={(length) => onChange({ ...layer, length })}
              />
              <AutoManualField
                id={`${id}-checksum`}
                label="Checksum"
                hint="IPv4 pseudo-header"
                allowHex
                hexDigits={4}
                value={layer.checksum}
                resolvedAutoValue={resolvedAutoValues?.checksum}
                error={fieldError('checksum')}
                warning={fieldWarning('checksum')}
                isHighlighted={isHighlighted('checksum')}
                onHoverStart={hoverStart('checksum')}
                onHoverEnd={hoverEnd}
                onChange={(checksum) => onChange({ ...layer, checksum })}
              />
            </div>
          )}

          {layer.type === 'tcp' && (
            <div className="field-grid">
              <NumberField
                id={`${id}-srcPort`}
                label="Source Port"
                hint="0-65535"
                value={layer.srcPort}
                error={fieldError('srcPort')}
                warning={fieldWarning('srcPort')}
                isHighlighted={isHighlighted('srcPort')}
                onHoverStart={hoverStart('srcPort')}
                onHoverEnd={hoverEnd}
                onChange={(srcPort) => onChange({ ...layer, srcPort })}
              />
              <NumberField
                id={`${id}-dstPort`}
                label="Destination Port"
                hint="0-65535"
                value={layer.dstPort}
                error={fieldError('dstPort')}
                warning={fieldWarning('dstPort')}
                isHighlighted={isHighlighted('dstPort')}
                onHoverStart={hoverStart('dstPort')}
                onHoverEnd={hoverEnd}
                onChange={(dstPort) => onChange({ ...layer, dstPort })}
              />
              <NumberField
                id={`${id}-seqNumber`}
                label="Sequence Number"
                hint="32 bit"
                value={layer.seqNumber}
                error={fieldError('seqNumber')}
                warning={fieldWarning('seqNumber')}
                isHighlighted={isHighlighted('seqNumber')}
                onHoverStart={hoverStart('seqNumber')}
                onHoverEnd={hoverEnd}
                onChange={(seqNumber) => onChange({ ...layer, seqNumber })}
              />
              <NumberField
                id={`${id}-ackNumber`}
                label="Acknowledgment Number"
                hint="32 bit"
                value={layer.ackNumber}
                error={fieldError('ackNumber')}
                warning={fieldWarning('ackNumber')}
                isHighlighted={isHighlighted('ackNumber')}
                onHoverStart={hoverStart('ackNumber')}
                onHoverEnd={hoverEnd}
                onChange={(ackNumber) => onChange({ ...layer, ackNumber })}
              />
              <NumberField
                id={`${id}-windowSize`}
                label="Window Size"
                hint="0-65535"
                value={layer.windowSize}
                error={fieldError('windowSize')}
                warning={fieldWarning('windowSize')}
                isHighlighted={isHighlighted('windowSize')}
                onHoverStart={hoverStart('windowSize')}
                onHoverEnd={hoverEnd}
                onChange={(windowSize) => onChange({ ...layer, windowSize })}
              />
              <NumberField
                id={`${id}-urgentPointer`}
                label="Urgent Pointer"
                hint="0-65535"
                value={layer.urgentPointer}
                error={fieldError('urgentPointer')}
                warning={fieldWarning('urgentPointer')}
                isHighlighted={isHighlighted('urgentPointer')}
                onHoverStart={hoverStart('urgentPointer')}
                onHoverEnd={hoverEnd}
                onChange={(urgentPointer) => onChange({ ...layer, urgentPointer })}
              />

              <div
                className={`field field-span-full${isHighlighted('flags') ? ' is-highlighted' : ''}`}
                onMouseEnter={hoverStart('flags')}
                onMouseLeave={hoverEnd}
              >
                <div className="field-label-row">
                  <span className="field-label">Control Bits</span>
                  <span className="field-hint">8 bit (RFC 9293 Section 3.1)</span>
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
                        onFocus={hoverStart('flags')}
                        onBlur={hoverEnd}
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
                hint="4 bit (base=5)"
                value={layer.dataOffset}
                resolvedAutoValue={resolvedAutoValues?.dataOffset}
                error={fieldError('dataOffset')}
                warning={fieldWarning('dataOffset')}
                isHighlighted={isHighlighted('dataOffset')}
                onHoverStart={hoverStart('dataOffset')}
                onHoverEnd={hoverEnd}
                onChange={(dataOffset) => onChange({ ...layer, dataOffset })}
              />
              <AutoManualField
                id={`${id}-checksum`}
                label="Checksum"
                hint="IPv4 pseudo-header"
                allowHex
                hexDigits={4}
                value={layer.checksum}
                resolvedAutoValue={resolvedAutoValues?.checksum}
                error={fieldError('checksum')}
                warning={fieldWarning('checksum')}
                isHighlighted={isHighlighted('checksum')}
                onHoverStart={hoverStart('checksum')}
                onHoverEnd={hoverEnd}
                onChange={(checksum) => onChange({ ...layer, checksum })}
              />

              <div className="fixed-field-row field-span-full">
                <FixedFieldChip
                  label="Reserved"
                  value="0"
                  bits="4b"
                  isHighlighted={isHighlighted('reserved')}
                  onHoverStart={hoverStart('reserved')}
                  onHoverEnd={hoverEnd}
                />
              </div>
            </div>
          )}

          {layer.type === 'bgp' && (
            <div className="field-grid">
              <div
                className={`field field-span-full${isHighlighted('bgpType') ? ' is-highlighted' : ''}`}
                onMouseEnter={hoverStart('bgpType')}
                onMouseLeave={hoverEnd}
              >
                <div className="field-label-row">
                  <span className="field-label">Message Type</span>
                  <span className="field-hint">8 bit (RFC 4271 §4.1)</span>
                </div>
                <div className="flag-chip-row" role="group" aria-label="BGP Message Type">
                  {BGP_TYPE_OPTIONS.map(({ type, label }) => (
                    <button
                      key={type}
                      type="button"
                      className={`preset-btn${layer.bgpType === type ? ' is-active' : ''}`}
                      aria-pressed={layer.bgpType === type}
                      onFocus={hoverStart('bgpType')}
                      onBlur={hoverEnd}
                      onClick={() => onChange({ ...layer, bgpType: type })}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              <AutoManualTextField
                id={`${id}-marker`}
                label="Marker"
                hint="16 bytes (0xff × 16)"
                fullWidth
                autoPreviewText="ff ff … ff (16 bytes)"
                manualSeedValue={BGP_DEFAULT_MARKER_HEX}
                placeholder={BGP_DEFAULT_MARKER_HEX}
                value={layer.marker}
                error={fieldError('marker')}
                warning={fieldWarning('marker')}
                isHighlighted={isHighlighted('marker')}
                onHoverStart={hoverStart('marker')}
                onHoverEnd={hoverEnd}
                onChange={(marker) => onChange({ ...layer, marker })}
              />

              <AutoManualField
                id={`${id}-length`}
                label="Length"
                hint="19-4096 bytes"
                value={layer.length}
                resolvedAutoValue={resolvedAutoValues?.length}
                error={fieldError('length')}
                warning={fieldWarning('length')}
                isHighlighted={isHighlighted('length')}
                onHoverStart={hoverStart('length')}
                onHoverEnd={hoverEnd}
                onChange={(length) => onChange({ ...layer, length })}
              />

              {layer.bgpType === 1 && (
                <>
                  <AutoManualField
                    id={`${id}-version`}
                    label="Version"
                    hint="4 = BGP-4"
                    value={layer.version}
                    resolvedAutoValue={resolvedAutoValues?.version}
                    error={fieldError('version')}
                    warning={fieldWarning('version')}
                    isHighlighted={isHighlighted('version')}
                    onHoverStart={hoverStart('version')}
                    onHoverEnd={hoverEnd}
                    onChange={(version) => onChange({ ...layer, version })}
                  />
                  <NumberField
                    id={`${id}-myAs`}
                    label="My AS"
                    hint="16 bit (0-65535)"
                    value={layer.myAs}
                    error={fieldError('myAs')}
                    warning={fieldWarning('myAs')}
                    isHighlighted={isHighlighted('myAs')}
                    onHoverStart={hoverStart('myAs')}
                    onHoverEnd={hoverEnd}
                    onChange={(myAs) => onChange({ ...layer, myAs })}
                  />
                  <NumberField
                    id={`${id}-holdTime`}
                    label="Hold Time"
                    hint="0 or 3-65535 sec"
                    value={layer.holdTime}
                    error={fieldError('holdTime')}
                    warning={fieldWarning('holdTime')}
                    isHighlighted={isHighlighted('holdTime')}
                    onHoverStart={hoverStart('holdTime')}
                    onHoverEnd={hoverEnd}
                    onChange={(holdTime) => onChange({ ...layer, holdTime })}
                  />
                  <TextField
                    id={`${id}-bgpIdentifier`}
                    label="BGP Identifier"
                    hint="32-bit IPv4"
                    placeholder="192.0.2.1"
                    value={layer.bgpIdentifier}
                    error={fieldError('bgpIdentifier')}
                    warning={fieldWarning('bgpIdentifier')}
                    isHighlighted={isHighlighted('bgpIdentifier')}
                    onHoverStart={hoverStart('bgpIdentifier')}
                    onHoverEnd={hoverEnd}
                    onChange={(bgpIdentifier) => onChange({ ...layer, bgpIdentifier })}
                  />
                  <AutoManualField
                    id={`${id}-optParamLength`}
                    label="Optional Parameters Length"
                    hint="0-255 bytes"
                    value={layer.optParamLength}
                    resolvedAutoValue={resolvedAutoValues?.optParamLength}
                    error={fieldError('optParamLength')}
                    warning={fieldWarning('optParamLength')}
                    isHighlighted={isHighlighted('optParamLength')}
                    onHoverStart={hoverStart('optParamLength')}
                    onHoverEnd={hoverEnd}
                    onChange={(optParamLength) => onChange({ ...layer, optParamLength })}
                  />
                </>
              )}

              {layer.bgpType === 2 && (
                <>
                  <AutoManualField
                    id={`${id}-withdrawnRoutesLength`}
                    label="Withdrawn Routes Length"
                    hint="16 bit (0 = none)"
                    value={layer.withdrawnRoutesLength}
                    resolvedAutoValue={resolvedAutoValues?.withdrawnRoutesLength}
                    error={fieldError('withdrawnRoutesLength')}
                    warning={fieldWarning('withdrawnRoutesLength')}
                    isHighlighted={isHighlighted('withdrawnRoutesLength')}
                    onHoverStart={hoverStart('withdrawnRoutesLength')}
                    onHoverEnd={hoverEnd}
                    onChange={(withdrawnRoutesLength) =>
                      onChange({ ...layer, withdrawnRoutesLength })
                    }
                  />
                  <AutoManualField
                    id={`${id}-totalPathAttrLength`}
                    label="Total Path Attribute Length"
                    hint="16 bit (bytes)"
                    value={layer.totalPathAttrLength}
                    resolvedAutoValue={resolvedAutoValues?.totalPathAttrLength}
                    error={fieldError('totalPathAttrLength')}
                    warning={fieldWarning('totalPathAttrLength')}
                    isHighlighted={isHighlighted('totalPathAttrLength')}
                    onHoverStart={hoverStart('totalPathAttrLength')}
                    onHoverEnd={hoverEnd}
                    onChange={(totalPathAttrLength) => onChange({ ...layer, totalPathAttrLength })}
                  />
                </>
              )}

              {layer.bgpType === 3 && (
                <>
                  <NumberField
                    id={`${id}-errorCode`}
                    label="Error Code"
                    hint="0-255 (1-6: RFC 4271, 7: RFC 7313)"
                    value={layer.errorCode}
                    error={fieldError('errorCode')}
                    warning={fieldWarning('errorCode')}
                    isHighlighted={isHighlighted('errorCode')}
                    onHoverStart={hoverStart('errorCode')}
                    onHoverEnd={hoverEnd}
                    onChange={(errorCode) => onChange({ ...layer, errorCode })}
                  />
                  <NumberField
                    id={`${id}-errorSubcode`}
                    label="Error Subcode"
                    hint="0-255"
                    value={layer.errorSubcode}
                    error={fieldError('errorSubcode')}
                    warning={fieldWarning('errorSubcode')}
                    isHighlighted={isHighlighted('errorSubcode')}
                    onHoverStart={hoverStart('errorSubcode')}
                    onHoverEnd={hoverEnd}
                    onChange={(errorSubcode) => onChange({ ...layer, errorSubcode })}
                  />
                </>
              )}

              {layer.bgpType === 4 && (
                <p className="field-hint field-span-full">
                  KEEPALIVE consists only of the 19-byte common BGP header with no payload (RFC 4271 §4.4).
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
