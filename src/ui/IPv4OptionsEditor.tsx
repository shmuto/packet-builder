import { useState } from 'react';
import type { FieldDoc } from '../core/fieldDocs';
import {
  decodeIPv4OptionTypeByte,
  getIPv4OptionsMetrics,
  getIPv4OptionTypeByte,
  IPV4_MAX_OPTIONS_LENGTH,
} from '../core/layers/ipv4';
import { autoValue, type IPv4Option } from '../core/layers/types';
import {
  AutoManualField,
  FixedFieldChip,
  NumberField,
  TextField,
} from './FieldControls';

type IPv4OptionKind = IPv4Option['kind'];

const IPV4_OPTION_KIND_CHOICES: readonly {
  readonly kind: IPv4OptionKind;
  readonly label: string;
  readonly sampleTypeByte: number;
}[] = [
  { kind: 'routerAlert', label: 'Router Alert (Type 148)', sampleTypeByte: 148 },
  { kind: 'rr', label: 'Record Route (Type 7)', sampleTypeByte: 7 },
  { kind: 'timestamp', label: 'Internet Timestamp (Type 68)', sampleTypeByte: 68 },
  { kind: 'lsrr', label: 'Loose Source Route (Type 131)', sampleTypeByte: 131 },
  { kind: 'ssrr', label: 'Strict Source Route (Type 137)', sampleTypeByte: 137 },
  { kind: 'nop', label: 'NOP (Type 1)', sampleTypeByte: 1 },
  { kind: 'eol', label: 'EOL (Type 0)', sampleTypeByte: 0 },
  { kind: 'raw', label: 'Raw Option (Custom)', sampleTypeByte: 134 },
];

function createDefaultIPv4Option(kind: IPv4OptionKind): IPv4Option {
  switch (kind) {
    case 'eol':
      return { kind: 'eol' };
    case 'nop':
      return { kind: 'nop' };
    case 'rr':
      return { kind: 'rr', pointer: autoValue(), addresses: ['0.0.0.0'] };
    case 'timestamp':
      return { kind: 'timestamp', pointer: 5, overflow: 0, flag: 0, dataHex: '00 00 00 00' };
    case 'lsrr':
      return { kind: 'lsrr', pointer: autoValue(), addresses: ['192.0.2.1'] };
    case 'ssrr':
      return { kind: 'ssrr', pointer: autoValue(), addresses: ['192.0.2.1'] };
    case 'routerAlert':
      return { kind: 'routerAlert', value: 0 };
    case 'raw':
      return { kind: 'raw', optionType: 134, length: autoValue(), dataHex: '00 00' };
  }
}

function getIPv4OptionTitle(opt: IPv4Option): string {
  switch (opt.kind) {
    case 'eol':
      return 'End of Option List (Type 0)';
    case 'nop':
      return 'No Operation (Type 1)';
    case 'rr':
      return 'Record Route (Type 7)';
    case 'timestamp':
      return 'Internet Timestamp (Type 68)';
    case 'lsrr':
      return 'Loose Source and Record Route (Type 131)';
    case 'ssrr':
      return 'Strict Source and Record Route (Type 137)';
    case 'routerAlert':
      return 'Router Alert (Type 148)';
    case 'raw':
      return `Raw Option (Type ${Number.isFinite(opt.optionType) ? opt.optionType : '?'})`;
  }
}

function formatTypeByteSummary(typeByte: number): string {
  const b = decodeIPv4OptionTypeByte(typeByte);
  return `copied=${b.copied} · class=${b.optionClass} · number=${b.number}`;
}

export interface IPv4OptionsEditorProps {
  readonly cardId: string;
  readonly options: readonly IPv4Option[];
  readonly resolvedAutoValues?: Readonly<Record<string, number>>;
  readonly fieldError: (fieldId: string) => string | undefined;
  readonly fieldWarning: (fieldId: string) => string | undefined;
  readonly fieldDoc: (fieldId: string) => FieldDoc | undefined;
  readonly isHighlighted: (fieldId: string) => boolean;
  readonly hoverStart: (fieldId: string) => () => void;
  readonly hoverEnd: () => void;
  readonly onChange: (nextOptions: readonly IPv4Option[]) => void;
}

export function IPv4OptionsEditor({
  cardId,
  options,
  resolvedAutoValues,
  fieldError,
  fieldWarning,
  fieldDoc,
  isHighlighted,
  hoverStart,
  hoverEnd,
  onChange,
}: IPv4OptionsEditorProps) {
  const [selectedKind, setSelectedKind] = useState<IPv4OptionKind>('routerAlert');
  const metrics = getIPv4OptionsMetrics(options);
  const optionsError = fieldError('options');
  const optionsWarning = fieldWarning('options');

  const selectedChoice =
    IPV4_OPTION_KIND_CHOICES.find((c) => c.kind === selectedKind) ?? IPV4_OPTION_KIND_CHOICES[0];

  const handleAdd = () => {
    onChange([...options, createDefaultIPv4Option(selectedKind)]);
  };

  const handleUpdate = (idx: number, next: IPv4Option) => {
    const copy = options.slice();
    copy[idx] = next;
    onChange(copy);
  };

  const handleRemove = (idx: number) => {
    onChange(options.filter((_, i) => i !== idx));
  };

  const handleMove = (idx: number, delta: -1 | 1) => {
    const target = idx + delta;
    if (target < 0 || target >= options.length) return;
    const copy = options.slice();
    const [moved] = copy.splice(idx, 1);
    copy.splice(target, 0, moved);
    onChange(copy);
  };

  return (
    <div className="options-section field-span-full" aria-label="IPv4 Options">
      <div className="options-header">
        <div className="options-title-group">
          <span className="field-label">Options</span>
          <span
            className={`options-size-badge mono${metrics.rawBytes > IPV4_MAX_OPTIONS_LENGTH ? ' is-error' : ''}`}
          >
            {metrics.rawBytes} / {IPV4_MAX_OPTIONS_LENGTH} B
          </span>
          {options.length > 0 && metrics.paddingBytes === 0 && (
            <span className="options-pad-note mono">0 B pad</span>
          )}
        </div>
        <div className="options-add-bar">
          <select
            className="options-kind-select"
            aria-label="IPv4 option type to add"
            value={selectedKind}
            onChange={(e) => setSelectedKind(e.target.value as IPv4OptionKind)}
          >
            {IPV4_OPTION_KIND_CHOICES.map((choice) => (
              <option key={choice.kind} value={choice.kind}>
                {choice.label}
              </option>
            ))}
          </select>
          <span className="option-type-bits mono" title="RFC 791 §3.1 option type byte breakdown">
            {formatTypeByteSummary(selectedChoice.sampleTypeByte)}
          </span>
          <button type="button" className="add-btn" onClick={handleAdd}>
            + Add Option
          </button>
        </div>
      </div>

      {optionsError && (
        <p className="field-msg is-error" role="alert">
          {optionsError}
        </p>
      )}
      {optionsWarning && <p className="field-msg is-warning">{optionsWarning}</p>}

      {options.length === 0 ? (
        <p className="options-empty">No IPv4 options (20-byte base header, IHL = 5).</p>
      ) : (
        <div className="options-list">
          {options.map((opt, i) => {
            const prefix = `options[${i}]`;
            const htmlPrefix = `${cardId}-options-${i}`;
            const typeByte = getIPv4OptionTypeByte(
              opt.kind,
              opt.kind === 'raw' && Number.isFinite(opt.optionType) ? opt.optionType : 0,
            );
            const parts = decodeIPv4OptionTypeByte(typeByte);

            const typeChips = (
              <>
                <FixedFieldChip
                  id={`${htmlPrefix}-copied`}
                  label="Copied"
                  value={String(parts.copied)}
                  bits="1b"
                  doc={fieldDoc(`${prefix}.copied`)}
                  isHighlighted={isHighlighted(`${prefix}.copied`)}
                  onHoverStart={hoverStart(`${prefix}.copied`)}
                  onHoverEnd={hoverEnd}
                />
                <FixedFieldChip
                  id={`${htmlPrefix}-class`}
                  label="Class"
                  value={String(parts.optionClass)}
                  bits="2b"
                  doc={fieldDoc(`${prefix}.class`)}
                  isHighlighted={isHighlighted(`${prefix}.class`)}
                  onHoverStart={hoverStart(`${prefix}.class`)}
                  onHoverEnd={hoverEnd}
                />
                <FixedFieldChip
                  id={`${htmlPrefix}-${opt.kind}-number`}
                  label="Number"
                  value={String(parts.number)}
                  bits="5b"
                  doc={fieldDoc(`${prefix}.${opt.kind}.number`)}
                  isHighlighted={isHighlighted(`${prefix}.${opt.kind}.number`)}
                  onHoverStart={hoverStart(`${prefix}.${opt.kind}.number`)}
                  onHoverEnd={hoverEnd}
                />
              </>
            );

            return (
              <div key={i} className="option-item">
                <div className="option-item-header">
                  <span className="option-item-title">
                    <span className="option-item-index mono">#{i + 1}</span>
                    <span>{getIPv4OptionTitle(opt)}</span>
                  </span>
                  <div className="option-item-actions">
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Move IPv4 option ${i + 1} up`}
                      disabled={i === 0}
                      onClick={() => handleMove(i, -1)}
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Move IPv4 option ${i + 1} down`}
                      disabled={i === options.length - 1}
                      onClick={() => handleMove(i, 1)}
                    >
                      ↓
                    </button>
                    <button
                      type="button"
                      className="icon-btn is-danger"
                      aria-label={`Remove IPv4 option ${i + 1}`}
                      onClick={() => handleRemove(i)}
                    >
                      ✕
                    </button>
                  </div>
                </div>

                {(opt.kind === 'eol' || opt.kind === 'nop') && (
                  <div className="fixed-field-row">{typeChips}</div>
                )}

                {(opt.kind === 'rr' || opt.kind === 'lsrr' || opt.kind === 'ssrr') && (() => {
                  const lenId = `${prefix}.${opt.kind}.length`;
                  const ptrId = `${prefix}.${opt.kind}.pointer`;
                  const numId = `${prefix}.${opt.kind}.number`;
                  const routeLen = 3 + opt.addresses.length * 4;

                  const addAddress = () => {
                    handleUpdate(i, {
                      ...opt,
                      addresses: [...opt.addresses, '0.0.0.0'],
                    });
                  };
                  const updateAddress = (aIdx: number, nextAddr: string) => {
                    const nextAddrs = opt.addresses.slice();
                    nextAddrs[aIdx] = nextAddr;
                    handleUpdate(i, { ...opt, addresses: nextAddrs });
                  };
                  const removeAddress = (aIdx: number) => {
                    handleUpdate(i, {
                      ...opt,
                      addresses: opt.addresses.filter((_, idx) => idx !== aIdx),
                    });
                  };

                  return (
                    <div className="option-item-body">
                      <div className="option-subbar">
                        <div className="fixed-field-row">
                          {typeChips}
                          <FixedFieldChip
                            id={`${htmlPrefix}-${opt.kind}-length`}
                            label="Length"
                            value={String(routeLen)}
                            bits="8b"
                            doc={fieldDoc(lenId)}
                            isHighlighted={isHighlighted(lenId)}
                            onHoverStart={hoverStart(lenId)}
                            onHoverEnd={hoverEnd}
                          />
                        </div>
                        <button type="button" className="add-btn" onClick={addAddress}>
                          + Add Hop
                        </button>
                      </div>
                      {fieldWarning(numId) && (
                        <p className="field-msg is-warning">{fieldWarning(numId)}</p>
                      )}
                      {fieldError(lenId) && (
                        <p className="field-msg is-error" role="alert">
                          {fieldError(lenId)}
                        </p>
                      )}
                      <AutoManualField
                        id={`${htmlPrefix}-${opt.kind}-pointer`}
                        label="Pointer"
                        hint="auto = 4 (4 + 4k)"
                        doc={fieldDoc(ptrId)}
                        value={opt.pointer}
                        resolvedAutoValue={resolvedAutoValues?.[ptrId]}
                        error={fieldError(ptrId)}
                        warning={fieldWarning(ptrId)}
                        isHighlighted={isHighlighted(ptrId)}
                        onHoverStart={hoverStart(ptrId)}
                        onHoverEnd={hoverEnd}
                        onChange={(pointer) => handleUpdate(i, { ...opt, pointer })}
                      />
                      {opt.addresses.map((addr, aIdx) => {
                        const addrId = `${prefix}.${opt.kind}.addrs[${aIdx}]`;
                        return (
                          <div key={aIdx} className="option-subitem">
                            <div className="option-subitem-header">
                              <span className="field-hint mono">Route Entry #{aIdx + 1}</span>
                              <button
                                type="button"
                                className="icon-btn is-danger"
                                aria-label={`Remove route entry ${aIdx + 1}`}
                                onClick={() => removeAddress(aIdx)}
                              >
                                ✕
                              </button>
                            </div>
                            <TextField
                              id={`${htmlPrefix}-${opt.kind}-addrs-${aIdx}`}
                              label={`IPv4 #${aIdx + 1}`}
                              hint="32 bit"
                              placeholder="192.0.2.1"
                              doc={fieldDoc(addrId)}
                              value={addr}
                              error={fieldError(addrId)}
                              warning={fieldWarning(addrId)}
                              isHighlighted={isHighlighted(addrId)}
                              onHoverStart={hoverStart(addrId)}
                              onHoverEnd={hoverEnd}
                              onChange={(val) => updateAddress(aIdx, val)}
                            />
                          </div>
                        );
                      })}
                    </div>
                  );
                })()}

                {opt.kind === 'timestamp' && (() => {
                  const lenId = `${prefix}.timestamp.length`;
                  const ptrId = `${prefix}.timestamp.pointer`;
                  const ovflId = `${prefix}.timestamp.overflow`;
                  const flagId = `${prefix}.timestamp.flag`;
                  const dataId = `${prefix}.timestamp.data`;
                  const compactLen = opt.dataHex.replace(/\s+/g, '').length;
                  const estLen = 4 + Math.floor(compactLen / 2);

                  return (
                    <div className="option-item-body">
                      <div className="fixed-field-row">
                        {typeChips}
                        <FixedFieldChip
                          id={`${htmlPrefix}-timestamp-length`}
                          label="Length"
                          value={String(estLen)}
                          bits="8b"
                          doc={fieldDoc(lenId)}
                          isHighlighted={isHighlighted(lenId)}
                          onHoverStart={hoverStart(lenId)}
                          onHoverEnd={hoverEnd}
                        />
                      </div>
                      {fieldError(lenId) && (
                        <p className="field-msg is-error" role="alert">
                          {fieldError(lenId)}
                        </p>
                      )}
                      <div className="field-grid">
                        <NumberField
                          id={`${htmlPrefix}-timestamp-pointer`}
                          label="Pointer"
                          hint="default 5 (8 bit)"
                          doc={fieldDoc(ptrId)}
                          value={opt.pointer}
                          error={fieldError(ptrId)}
                          warning={fieldWarning(ptrId)}
                          isHighlighted={isHighlighted(ptrId)}
                          onHoverStart={hoverStart(ptrId)}
                          onHoverEnd={hoverEnd}
                          onChange={(pointer) => handleUpdate(i, { ...opt, pointer })}
                        />
                        <NumberField
                          id={`${htmlPrefix}-timestamp-overflow`}
                          label="Overflow (Oflw)"
                          hint="0-15 (4 bit)"
                          doc={fieldDoc(ovflId)}
                          value={opt.overflow}
                          error={fieldError(ovflId)}
                          warning={fieldWarning(ovflId)}
                          isHighlighted={isHighlighted(ovflId)}
                          onHoverStart={hoverStart(ovflId)}
                          onHoverEnd={hoverEnd}
                          onChange={(overflow) => handleUpdate(i, { ...opt, overflow })}
                        />
                        <NumberField
                          id={`${htmlPrefix}-timestamp-flag`}
                          label="Flag"
                          hint="0=TS / 1=IP+TS / 3=Pre"
                          doc={fieldDoc(flagId)}
                          value={opt.flag}
                          error={fieldError(flagId)}
                          warning={fieldWarning(flagId)}
                          isHighlighted={isHighlighted(flagId)}
                          onHoverStart={hoverStart(flagId)}
                          onHoverEnd={hoverEnd}
                          onChange={(flag) => handleUpdate(i, { ...opt, flag })}
                        />
                        <div className="field-span-full">
                          <TextField
                            id={`${htmlPrefix}-timestamp-data`}
                            label="Timestamp Data (Hex)"
                            hint="bytes"
                            placeholder="00 00 00 00"
                            doc={fieldDoc(dataId)}
                            value={opt.dataHex}
                            error={fieldError(dataId)}
                            warning={fieldWarning(dataId)}
                            isHighlighted={isHighlighted(dataId)}
                            onHoverStart={hoverStart(dataId)}
                            onHoverEnd={hoverEnd}
                            onChange={(dataHex) => handleUpdate(i, { ...opt, dataHex })}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {opt.kind === 'routerAlert' && (
                  <div className="option-item-body">
                    <div className="fixed-field-row">
                      {typeChips}
                      <FixedFieldChip
                        id={`${htmlPrefix}-routerAlert-length`}
                        label="Length"
                        value="4"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.routerAlert.length`)}
                        isHighlighted={isHighlighted(`${prefix}.routerAlert.length`)}
                        onHoverStart={hoverStart(`${prefix}.routerAlert.length`)}
                        onHoverEnd={hoverEnd}
                      />
                    </div>
                    <NumberField
                      id={`${htmlPrefix}-routerAlert-value`}
                      label="Value"
                      hint="0 = Router shall examine packet (16 bit)"
                      doc={fieldDoc(`${prefix}.routerAlert.value`)}
                      value={opt.value}
                      error={fieldError(`${prefix}.routerAlert.value`)}
                      warning={fieldWarning(`${prefix}.routerAlert.value`)}
                      isHighlighted={isHighlighted(`${prefix}.routerAlert.value`)}
                      onHoverStart={hoverStart(`${prefix}.routerAlert.value`)}
                      onHoverEnd={hoverEnd}
                      onChange={(value) => handleUpdate(i, { ...opt, value })}
                    />
                  </div>
                )}

                {opt.kind === 'raw' && (
                  <div className="option-item-body">
                    <div className="fixed-field-row">{typeChips}</div>
                    <div className="field-grid">
                      <NumberField
                        id={`${htmlPrefix}-raw-type`}
                        label="Option Type"
                        hint="0-255 (copied/class/num)"
                        value={opt.optionType}
                        error={fieldError(`${prefix}.raw.number`)}
                        warning={fieldWarning(`${prefix}.raw.number`)}
                        isHighlighted={isHighlighted(`${prefix}.raw.number`)}
                        onHoverStart={hoverStart(`${prefix}.raw.number`)}
                        onHoverEnd={hoverEnd}
                        onChange={(optionType) => handleUpdate(i, { ...opt, optionType })}
                      />
                      {opt.length.mode === 'none' ? (
                        <div className="field">
                          <div className="field-label-row">
                            <span className="field-label">Length</span>
                            <button
                              type="button"
                              className="mode-btn"
                              onClick={() => handleUpdate(i, { ...opt, length: autoValue() })}
                            >
                              Switch to TLV Auto
                            </button>
                          </div>
                          <div className="field-auto-preview mono">
                            <span className="auto-tag">RAW</span>
                            <span className="auto-val">Omitted (verbatim bytes)</span>
                          </div>
                        </div>
                      ) : (
                        <AutoManualField
                          id={`${htmlPrefix}-raw-length`}
                          label="Length"
                          hint="2 + data bytes"
                          doc={fieldDoc(`${prefix}.raw.length`)}
                          value={opt.length}
                          resolvedAutoValue={resolvedAutoValues?.[`${prefix}.raw.length`]}
                          error={fieldError(`${prefix}.raw.length`)}
                          warning={fieldWarning(`${prefix}.raw.length`)}
                          isHighlighted={isHighlighted(`${prefix}.raw.length`)}
                          onHoverStart={hoverStart(`${prefix}.raw.length`)}
                          onHoverEnd={hoverEnd}
                          onChange={(length) => handleUpdate(i, { ...opt, length })}
                        />
                      )}
                      <div className="field-span-full">
                        <TextField
                          id={`${htmlPrefix}-raw-data`}
                          label="Data (Hex)"
                          hint="bytes"
                          placeholder="aa bb"
                          doc={fieldDoc(`${prefix}.raw.data`)}
                          value={opt.dataHex}
                          error={fieldError(`${prefix}.raw.data`)}
                          warning={fieldWarning(`${prefix}.raw.data`)}
                          isHighlighted={isHighlighted(`${prefix}.raw.data`)}
                          onHoverStart={hoverStart(`${prefix}.raw.data`)}
                          onHoverEnd={hoverEnd}
                          onChange={(dataHex) => handleUpdate(i, { ...opt, dataHex })}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {metrics.paddingBytes > 0 && (
        <div className="options-padding-row">
          <FixedFieldChip
            id={`${cardId}-optionsPadding`}
            label="Options Padding"
            value={`${metrics.paddingBytes} B (${Array(metrics.paddingBytes).fill('00').join(' ')})`}
            bits={`${metrics.paddingBytes * 8}b`}
            doc={fieldDoc('optionsPadding')}
            isHighlighted={isHighlighted('optionsPadding')}
            onHoverStart={hoverStart('optionsPadding')}
            onHoverEnd={hoverEnd}
          />
        </div>
      )}
    </div>
  );
}
