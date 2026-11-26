import { useState } from 'react';
import type { FieldDoc } from '../core/fieldDocs';
import { getTCPOptionsMetrics, TCP_MAX_OPTIONS_LENGTH } from '../core/layers/tcp';
import {
  autoValue,
  type TCPOption,
  type TCPSackBlock,
} from '../core/layers/types';
import {
  AutoManualField,
  FixedFieldChip,
  NumberField,
  TextField,
} from './FieldControls';

type TCPOptionKind = TCPOption['kind'];

const TCP_OPTION_KIND_CHOICES: readonly {
  readonly kind: TCPOptionKind;
  readonly label: string;
}[] = [
  { kind: 'mss', label: 'MSS (Kind 2)' },
  { kind: 'windowScale', label: 'Window Scale (Kind 3)' },
  { kind: 'sackPermitted', label: 'SACK-Permitted (Kind 4)' },
  { kind: 'sack', label: 'SACK (Kind 5)' },
  { kind: 'timestamps', label: 'Timestamps (Kind 8)' },
  { kind: 'nop', label: 'NOP (Kind 1)' },
  { kind: 'eol', label: 'EOL (Kind 0)' },
  { kind: 'raw', label: 'Raw Option (Custom)' },
];

function createDefaultTCPOption(kind: TCPOptionKind): TCPOption {
  switch (kind) {
    case 'eol':
      return { kind: 'eol' };
    case 'nop':
      return { kind: 'nop' };
    case 'mss':
      return { kind: 'mss', mss: 1460 };
    case 'windowScale':
      return { kind: 'windowScale', shiftCount: 7 };
    case 'sackPermitted':
      return { kind: 'sackPermitted' };
    case 'sack':
      return { kind: 'sack', blocks: [{ left: 2000, right: 3000 }] };
    case 'timestamps':
      return { kind: 'timestamps', tsVal: 1000000, tsEcr: 0 };
    case 'raw':
      return { kind: 'raw', optionKind: 30, length: autoValue(), dataHex: '00 00' };
  }
}

function getTCPOptionTitle(opt: TCPOption): string {
  switch (opt.kind) {
    case 'eol':
      return 'End of Option List (Kind 0)';
    case 'nop':
      return 'No-Operation (Kind 1)';
    case 'mss':
      return 'Maximum Segment Size (Kind 2)';
    case 'windowScale':
      return 'Window Scale (Kind 3)';
    case 'sackPermitted':
      return 'SACK-Permitted (Kind 4)';
    case 'sack':
      return 'SACK (Kind 5)';
    case 'timestamps':
      return 'Timestamps (Kind 8)';
    case 'raw':
      return `Raw Option (Kind ${Number.isFinite(opt.optionKind) ? opt.optionKind : '?'})`;
  }
}

export interface TCPOptionsEditorProps {
  readonly cardId: string;
  readonly options: readonly TCPOption[];
  readonly resolvedAutoValues?: Readonly<Record<string, number>>;
  readonly fieldError: (fieldId: string) => string | undefined;
  readonly fieldWarning: (fieldId: string) => string | undefined;
  readonly fieldDoc: (fieldId: string) => FieldDoc | undefined;
  readonly isHighlighted: (fieldId: string) => boolean;
  readonly hoverStart: (fieldId: string) => () => void;
  readonly hoverEnd: () => void;
  readonly onChange: (nextOptions: readonly TCPOption[]) => void;
}

export function TCPOptionsEditor({
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
}: TCPOptionsEditorProps) {
  const [selectedKind, setSelectedKind] = useState<TCPOptionKind>('mss');
  const metrics = getTCPOptionsMetrics(options);
  const optionsError = fieldError('options');
  const optionsWarning = fieldWarning('options');

  const handleAdd = () => {
    onChange([...options, createDefaultTCPOption(selectedKind)]);
  };

  const handleUpdate = (idx: number, next: TCPOption) => {
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
    <div className="options-section field-span-full" aria-label="TCP Options">
      <div className="options-header">
        <div className="options-title-group">
          <span className="field-label">Options</span>
          <span
            className={`options-size-badge mono${metrics.rawBytes > TCP_MAX_OPTIONS_LENGTH ? ' is-error' : ''}`}
          >
            {metrics.rawBytes} / {TCP_MAX_OPTIONS_LENGTH} B
          </span>
          {options.length > 0 && metrics.paddingBytes === 0 && (
            <span className="options-pad-note mono">0 B pad</span>
          )}
        </div>
        <div className="options-add-bar">
          <select
            className="options-kind-select"
            aria-label="TCP option kind to add"
            value={selectedKind}
            onChange={(e) => setSelectedKind(e.target.value as TCPOptionKind)}
          >
            {TCP_OPTION_KIND_CHOICES.map((choice) => (
              <option key={choice.kind} value={choice.kind}>
                {choice.label}
              </option>
            ))}
          </select>
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
        <p className="options-empty">No TCP options (20-byte base header, Data Offset = 5).</p>
      ) : (
        <div className="options-list">
          {options.map((opt, i) => {
            const prefix = `options[${i}]`;
            const htmlPrefix = `${cardId}-options-${i}`;

            return (
              <div key={i} className="option-item">
                <div className="option-item-header">
                  <span className="option-item-title">
                    <span className="option-item-index mono">#{i + 1}</span>
                    <span>{getTCPOptionTitle(opt)}</span>
                  </span>
                  <div className="option-item-actions">
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Move TCP option ${i + 1} up`}
                      disabled={i === 0}
                      onClick={() => handleMove(i, -1)}
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Move TCP option ${i + 1} down`}
                      disabled={i === options.length - 1}
                      onClick={() => handleMove(i, 1)}
                    >
                      ↓
                    </button>
                    <button
                      type="button"
                      className="icon-btn is-danger"
                      aria-label={`Remove TCP option ${i + 1}`}
                      onClick={() => handleRemove(i)}
                    >
                      ✕
                    </button>
                  </div>
                </div>

                {opt.kind === 'eol' && (
                  <div className="fixed-field-row">
                    <FixedFieldChip
                      id={`${htmlPrefix}-eol-kind`}
                      label="Kind"
                      value="0 (EOL)"
                      bits="8b"
                      doc={fieldDoc(`${prefix}.eol.kind`)}
                      isHighlighted={isHighlighted(`${prefix}.eol.kind`)}
                      onHoverStart={hoverStart(`${prefix}.eol.kind`)}
                      onHoverEnd={hoverEnd}
                    />
                  </div>
                )}

                {opt.kind === 'nop' && (
                  <div className="fixed-field-row">
                    <FixedFieldChip
                      id={`${htmlPrefix}-nop-kind`}
                      label="Kind"
                      value="1 (NOP)"
                      bits="8b"
                      doc={fieldDoc(`${prefix}.nop.kind`)}
                      isHighlighted={isHighlighted(`${prefix}.nop.kind`)}
                      onHoverStart={hoverStart(`${prefix}.nop.kind`)}
                      onHoverEnd={hoverEnd}
                    />
                  </div>
                )}

                {opt.kind === 'mss' && (
                  <div className="option-item-body">
                    <div className="fixed-field-row">
                      <FixedFieldChip
                        id={`${htmlPrefix}-mss-kind`}
                        label="Kind"
                        value="2"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.mss.kind`)}
                        isHighlighted={isHighlighted(`${prefix}.mss.kind`)}
                        onHoverStart={hoverStart(`${prefix}.mss.kind`)}
                        onHoverEnd={hoverEnd}
                      />
                      <FixedFieldChip
                        id={`${htmlPrefix}-mss-length`}
                        label="Length"
                        value="4"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.mss.length`)}
                        isHighlighted={isHighlighted(`${prefix}.mss.length`)}
                        onHoverStart={hoverStart(`${prefix}.mss.length`)}
                        onHoverEnd={hoverEnd}
                      />
                    </div>
                    <NumberField
                      id={`${htmlPrefix}-mss-mss`}
                      label="MSS"
                      hint="0-65535 (16 bit)"
                      doc={fieldDoc(`${prefix}.mss.mss`)}
                      value={opt.mss}
                      error={fieldError(`${prefix}.mss.mss`)}
                      warning={fieldWarning(`${prefix}.mss.mss`)}
                      isHighlighted={isHighlighted(`${prefix}.mss.mss`)}
                      onHoverStart={hoverStart(`${prefix}.mss.mss`)}
                      onHoverEnd={hoverEnd}
                      onChange={(mss) => handleUpdate(i, { ...opt, mss })}
                    />
                  </div>
                )}

                {opt.kind === 'windowScale' && (
                  <div className="option-item-body">
                    <div className="fixed-field-row">
                      <FixedFieldChip
                        id={`${htmlPrefix}-windowScale-kind`}
                        label="Kind"
                        value="3"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.windowScale.kind`)}
                        isHighlighted={isHighlighted(`${prefix}.windowScale.kind`)}
                        onHoverStart={hoverStart(`${prefix}.windowScale.kind`)}
                        onHoverEnd={hoverEnd}
                      />
                      <FixedFieldChip
                        id={`${htmlPrefix}-windowScale-length`}
                        label="Length"
                        value="3"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.windowScale.length`)}
                        isHighlighted={isHighlighted(`${prefix}.windowScale.length`)}
                        onHoverStart={hoverStart(`${prefix}.windowScale.length`)}
                        onHoverEnd={hoverEnd}
                      />
                    </div>
                    <NumberField
                      id={`${htmlPrefix}-windowScale-shiftCount`}
                      label="Shift Count"
                      hint="0-14 valid (8 bit)"
                      doc={fieldDoc(`${prefix}.windowScale.shiftCount`)}
                      value={opt.shiftCount}
                      error={fieldError(`${prefix}.windowScale.shiftCount`)}
                      warning={fieldWarning(`${prefix}.windowScale.shiftCount`)}
                      isHighlighted={isHighlighted(`${prefix}.windowScale.shiftCount`)}
                      onHoverStart={hoverStart(`${prefix}.windowScale.shiftCount`)}
                      onHoverEnd={hoverEnd}
                      onChange={(shiftCount) => handleUpdate(i, { ...opt, shiftCount })}
                    />
                  </div>
                )}

                {opt.kind === 'sackPermitted' && (
                  <div className="option-item-body">
                    <div className="fixed-field-row">
                      <FixedFieldChip
                        id={`${htmlPrefix}-sackPermitted-kind`}
                        label="Kind"
                        value="4"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.sackPermitted.kind`)}
                        isHighlighted={isHighlighted(`${prefix}.sackPermitted.kind`)}
                        onHoverStart={hoverStart(`${prefix}.sackPermitted.kind`)}
                        onHoverEnd={hoverEnd}
                      />
                      <FixedFieldChip
                        id={`${htmlPrefix}-sackPermitted-length`}
                        label="Length"
                        value="2"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.sackPermitted.length`)}
                        isHighlighted={isHighlighted(`${prefix}.sackPermitted.length`)}
                        onHoverStart={hoverStart(`${prefix}.sackPermitted.length`)}
                        onHoverEnd={hoverEnd}
                      />
                    </div>
                    {fieldWarning(`${prefix}.sackPermitted.kind`) && (
                      <p className="field-msg is-warning">
                        {fieldWarning(`${prefix}.sackPermitted.kind`)}
                      </p>
                    )}
                  </div>
                )}

                {opt.kind === 'sack' && (() => {
                  const lenFieldId = `${prefix}.sack.length`;
                  const sackLen = 2 + opt.blocks.length * 8;
                  const updateBlock = (bIdx: number, nextBlock: TCPSackBlock) => {
                    const nextBlocks = opt.blocks.slice();
                    nextBlocks[bIdx] = nextBlock;
                    handleUpdate(i, { ...opt, blocks: nextBlocks });
                  };
                  const addBlock = () => {
                    const lastRight =
                      opt.blocks.length > 0 ? opt.blocks[opt.blocks.length - 1].right : 1000;
                    const nextLeft = (lastRight + 1000) >>> 0;
                    const nextRight = (nextLeft + 1000) >>> 0;
                    handleUpdate(i, {
                      ...opt,
                      blocks: [...opt.blocks, { left: nextLeft, right: nextRight }],
                    });
                  };
                  const removeBlock = (bIdx: number) => {
                    handleUpdate(i, {
                      ...opt,
                      blocks: opt.blocks.filter((_, idx) => idx !== bIdx),
                    });
                  };

                  return (
                    <div className="option-item-body">
                      <div className="option-subbar">
                        <div className="fixed-field-row">
                          <FixedFieldChip
                            id={`${htmlPrefix}-sack-kind`}
                            label="Kind"
                            value="5"
                            bits="8b"
                            doc={fieldDoc(`${prefix}.sack.kind`)}
                            isHighlighted={isHighlighted(`${prefix}.sack.kind`)}
                            onHoverStart={hoverStart(`${prefix}.sack.kind`)}
                            onHoverEnd={hoverEnd}
                          />
                          <FixedFieldChip
                            id={`${htmlPrefix}-sack-length`}
                            label="Length"
                            value={String(sackLen)}
                            bits="8b"
                            doc={fieldDoc(lenFieldId)}
                            isHighlighted={isHighlighted(lenFieldId)}
                            onHoverStart={hoverStart(lenFieldId)}
                            onHoverEnd={hoverEnd}
                          />
                        </div>
                        <button type="button" className="add-btn" onClick={addBlock}>
                          + Add Block
                        </button>
                      </div>
                      {fieldError(lenFieldId) && (
                        <p className="field-msg is-error" role="alert">
                          {fieldError(lenFieldId)}
                        </p>
                      )}
                      {fieldWarning(lenFieldId) && (
                        <p className="field-msg is-warning">{fieldWarning(lenFieldId)}</p>
                      )}
                      {opt.blocks.map((block, bIdx) => {
                        const leftId = `${prefix}.sack.blocks[${bIdx}].left`;
                        const rightId = `${prefix}.sack.blocks[${bIdx}].right`;
                        return (
                          <div key={bIdx} className="option-subitem">
                            <div className="option-subitem-header">
                              <span className="field-hint mono">Block #{bIdx + 1}</span>
                              <button
                                type="button"
                                className="icon-btn is-danger"
                                aria-label={`Remove SACK block ${bIdx + 1}`}
                                onClick={() => removeBlock(bIdx)}
                              >
                                ✕
                              </button>
                            </div>
                            <div className="field-grid">
                              <NumberField
                                id={`${htmlPrefix}-sack-blocks-${bIdx}-left`}
                                label="Left Edge"
                                hint="32 bit"
                                doc={fieldDoc(leftId)}
                                value={block.left}
                                error={fieldError(leftId)}
                                warning={fieldWarning(leftId)}
                                isHighlighted={isHighlighted(leftId)}
                                onHoverStart={hoverStart(leftId)}
                                onHoverEnd={hoverEnd}
                                onChange={(left) => updateBlock(bIdx, { ...block, left })}
                              />
                              <NumberField
                                id={`${htmlPrefix}-sack-blocks-${bIdx}-right`}
                                label="Right Edge"
                                hint="32 bit"
                                doc={fieldDoc(rightId)}
                                value={block.right}
                                error={fieldError(rightId)}
                                warning={fieldWarning(rightId)}
                                isHighlighted={isHighlighted(rightId)}
                                onHoverStart={hoverStart(rightId)}
                                onHoverEnd={hoverEnd}
                                onChange={(right) => updateBlock(bIdx, { ...block, right })}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  );
                })()}

                {opt.kind === 'timestamps' && (
                  <div className="option-item-body">
                    <div className="fixed-field-row">
                      <FixedFieldChip
                        id={`${htmlPrefix}-timestamps-kind`}
                        label="Kind"
                        value="8"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.timestamps.kind`)}
                        isHighlighted={isHighlighted(`${prefix}.timestamps.kind`)}
                        onHoverStart={hoverStart(`${prefix}.timestamps.kind`)}
                        onHoverEnd={hoverEnd}
                      />
                      <FixedFieldChip
                        id={`${htmlPrefix}-timestamps-length`}
                        label="Length"
                        value="10"
                        bits="8b"
                        doc={fieldDoc(`${prefix}.timestamps.length`)}
                        isHighlighted={isHighlighted(`${prefix}.timestamps.length`)}
                        onHoverStart={hoverStart(`${prefix}.timestamps.length`)}
                        onHoverEnd={hoverEnd}
                      />
                    </div>
                    <div className="field-grid">
                      <NumberField
                        id={`${htmlPrefix}-timestamps-tsVal`}
                        label="TSval"
                        hint="32 bit"
                        doc={fieldDoc(`${prefix}.timestamps.tsVal`)}
                        value={opt.tsVal}
                        error={fieldError(`${prefix}.timestamps.tsVal`)}
                        warning={fieldWarning(`${prefix}.timestamps.tsVal`)}
                        isHighlighted={isHighlighted(`${prefix}.timestamps.tsVal`)}
                        onHoverStart={hoverStart(`${prefix}.timestamps.tsVal`)}
                        onHoverEnd={hoverEnd}
                        onChange={(tsVal) => handleUpdate(i, { ...opt, tsVal })}
                      />
                      <NumberField
                        id={`${htmlPrefix}-timestamps-tsEcr`}
                        label="TSecr"
                        hint="32 bit"
                        doc={fieldDoc(`${prefix}.timestamps.tsEcr`)}
                        value={opt.tsEcr}
                        error={fieldError(`${prefix}.timestamps.tsEcr`)}
                        warning={fieldWarning(`${prefix}.timestamps.tsEcr`)}
                        isHighlighted={isHighlighted(`${prefix}.timestamps.tsEcr`)}
                        onHoverStart={hoverStart(`${prefix}.timestamps.tsEcr`)}
                        onHoverEnd={hoverEnd}
                        onChange={(tsEcr) => handleUpdate(i, { ...opt, tsEcr })}
                      />
                    </div>
                  </div>
                )}

                {opt.kind === 'raw' && (
                  <div className="option-item-body">
                    <div className="field-grid">
                      <NumberField
                        id={`${htmlPrefix}-raw-kind`}
                        label="Option Kind"
                        hint="0-255 (8 bit)"
                        doc={fieldDoc(`${prefix}.raw.kind`)}
                        value={opt.optionKind}
                        error={fieldError(`${prefix}.raw.kind`)}
                        warning={fieldWarning(`${prefix}.raw.kind`)}
                        isHighlighted={isHighlighted(`${prefix}.raw.kind`)}
                        onHoverStart={hoverStart(`${prefix}.raw.kind`)}
                        onHoverEnd={hoverEnd}
                        onChange={(optionKind) => handleUpdate(i, { ...opt, optionKind })}
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
                        <div className="option-item-body">
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
                          <button
                            type="button"
                            className="mode-btn"
                            onClick={() =>
                              handleUpdate(i, { ...opt, length: { mode: 'none' } })
                            }
                          >
                            Omit Length (Raw bytes)
                          </button>
                        </div>
                      )}
                      <div className="field-span-full">
                        <TextField
                          id={`${htmlPrefix}-raw-data`}
                          label="Data (Hex)"
                          hint="bytes"
                          placeholder="aa bb cc"
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
