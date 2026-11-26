import { useEffect, useState } from 'react';
import type { FieldDoc } from '../core/fieldDocs';
import { formatHex, parseUnsignedIntInput } from '../core/inspector';
import { autoValue, manualValue, type AutoOrManual } from '../core/layers/types';

interface BaseFieldProps {
  readonly id: string;
  readonly label: string;
  readonly hint?: string;
  readonly doc?: FieldDoc;
  readonly error?: string;
  readonly warning?: string;
  readonly isHighlighted?: boolean;
  readonly onHoverStart?: () => void;
  readonly onHoverEnd?: () => void;
}

function getFeedbackId(id: string, error?: string, warning?: string): string | undefined {
  if (error) return `${id}-error`;
  if (warning) return `${id}-warning`;
  return undefined;
}

function joinDescribedBy(...ids: readonly (string | undefined)[]): string | undefined {
  const present = ids.filter((id): id is string => Boolean(id));
  return present.length > 0 ? present.join(' ') : undefined;
}

export interface FieldInfoButtonProps {
  readonly label: string;
  readonly docId: string;
  readonly open: boolean;
  readonly onToggle: () => void;
  readonly onClose: () => void;
  readonly onFocus?: () => void;
  readonly onBlur?: () => void;
}

/** Keyboard- and touch-accessible disclosure toggle that reveals a field's RFC explanation. */
export function FieldInfoButton({
  label,
  docId,
  open,
  onToggle,
  onClose,
  onFocus,
  onBlur,
}: FieldInfoButtonProps) {
  return (
    <button
      type="button"
      className={`field-info-btn${open ? ' is-open' : ''}`}
      aria-label={`Explain ${label}`}
      aria-expanded={open}
      aria-controls={docId}
      title={`Explain ${label}`}
      onClick={onToggle}
      onFocus={onFocus}
      onBlur={onBlur}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && open) {
          e.stopPropagation();
          onClose();
        }
      }}
    >
      i
    </button>
  );
}

export interface FieldDocBoxProps {
  readonly id: string;
  readonly doc: FieldDoc;
}

/** Inline explanation card showing plain-English field summary and RFC/IEEE section reference. */
export function FieldDocBox({ id, doc }: FieldDocBoxProps) {
  return (
    <div id={id} className="field-doc-box">
      <p className="field-doc-summary">{doc.summary}</p>
      <span className="field-doc-ref mono">{doc.reference}</span>
    </div>
  );
}

function FieldFeedback({
  id,
  error,
  warning,
}: {
  readonly id: string;
  readonly error?: string;
  readonly warning?: string;
}) {
  if (error) {
    return (
      <p id={`${id}-error`} className="field-msg is-error" role="alert">
        {error}
      </p>
    );
  }
  if (warning) {
    return (
      <p id={`${id}-warning`} className="field-msg is-warning">
        {warning}
      </p>
    );
  }
  return null;
}

export interface FixedFieldChipProps {
  readonly id?: string;
  readonly label: string;
  readonly value: string;
  readonly bits: string;
  readonly doc?: FieldDoc;
  readonly isHighlighted?: boolean;
  readonly onHoverStart?: () => void;
  readonly onHoverEnd?: () => void;
}

/** Read-only fixed header field chip (e.g., IPv4 Version=4, IHL=5, TCP Reserved=0) with hover sync and tap/keyboard doc toggle. */
export function FixedFieldChip({
  id,
  label,
  value,
  bits,
  doc,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
}: FixedFieldChipProps) {
  const [infoOpen, setInfoOpen] = useState(false);
  const docId = id ? `${id}-doc` : undefined;

  if (!doc) {
    return (
      <span
        tabIndex={0}
        className={`fixed-field-chip mono${isHighlighted ? ' is-highlighted' : ''}`}
        onMouseEnter={onHoverStart}
        onMouseLeave={onHoverEnd}
        onFocus={onHoverStart}
        onBlur={onHoverEnd}
      >
        <span className="fixed-field-name">{label}</span>
        <span className="fixed-field-val">{value}</span>
        <span className="fixed-field-bits">{bits}</span>
      </span>
    );
  }

  return (
    <div className={`fixed-field-item${infoOpen ? ' is-expanded' : ''}`}>
      <button
        type="button"
        className={`fixed-field-chip is-interactive mono${isHighlighted ? ' is-highlighted' : ''}${infoOpen ? ' is-open' : ''}`}
        aria-expanded={infoOpen}
        aria-controls={docId}
        aria-describedby={infoOpen ? docId : undefined}
        onClick={() => setInfoOpen((prev) => !prev)}
        onMouseEnter={onHoverStart}
        onMouseLeave={onHoverEnd}
        onFocus={onHoverStart}
        onBlur={onHoverEnd}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && infoOpen) {
            e.stopPropagation();
            setInfoOpen(false);
          }
        }}
      >
        <span className="fixed-field-name">{label}</span>
        <span className="fixed-field-val">{value}</span>
        <span className="fixed-field-bits">{bits}</span>
        <span className="fixed-field-info-mark" aria-hidden="true">
          i
        </span>
      </button>
      {infoOpen && docId && <FieldDocBox id={docId} doc={doc} />}
    </div>
  );
}

export interface TextFieldProps extends BaseFieldProps {
  readonly value: string;
  readonly placeholder?: string;
  readonly onChange: (next: string) => void;
}

export function TextField({
  id,
  label,
  hint,
  doc,
  error,
  warning,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
  value,
  placeholder,
  onChange,
}: TextFieldProps) {
  const [infoOpen, setInfoOpen] = useState(false);
  const docId = `${id}-doc`;
  const describedBy = joinDescribedBy(getFeedbackId(id, error, warning), doc && infoOpen ? docId : undefined);

  return (
    <div
      className={`field${isHighlighted ? ' is-highlighted' : ''}`}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <div className="field-label-row">
        <div className="field-label-main">
          <label className="field-label" htmlFor={id}>
            {label}
          </label>
          {doc && (
            <FieldInfoButton
              label={label}
              docId={docId}
              open={infoOpen}
              onToggle={() => setInfoOpen((prev) => !prev)}
              onClose={() => setInfoOpen(false)}
              onFocus={onHoverStart}
              onBlur={onHoverEnd}
            />
          )}
        </div>
        {hint && <span className="field-hint">{hint}</span>}
      </div>
      <input
        id={id}
        type="text"
        className={`field-input mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
        value={value}
        placeholder={placeholder}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        onFocus={onHoverStart}
        onBlur={onHoverEnd}
        onChange={(e) => onChange(e.target.value)}
      />
      {doc && infoOpen && <FieldDocBox id={docId} doc={doc} />}
      <FieldFeedback id={id} error={error} warning={warning} />
    </div>
  );
}

export interface NumberFieldProps extends BaseFieldProps {
  readonly value: number;
  readonly allowHex?: boolean;
  readonly hexDigits?: number;
  readonly placeholder?: string;
  readonly onChange: (next: number) => void;
}

function formatNumberDraft(value: number, hexDigits?: number): string {
  if (Number.isNaN(value)) {
    return '';
  }
  return hexDigits ? formatHex(value, hexDigits) : String(value);
}

export function NumberField({
  id,
  label,
  hint,
  doc,
  error,
  warning,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
  value,
  allowHex = false,
  hexDigits,
  placeholder,
  onChange,
}: NumberFieldProps) {
  const [draft, setDraft] = useState<string>(() => formatNumberDraft(value, hexDigits));
  const [infoOpen, setInfoOpen] = useState(false);

  useEffect(() => {
    const parsedDraft = parseUnsignedIntInput(draft, allowHex);
    if (Number.isNaN(value)) {
      return;
    }
    if (parsedDraft !== value) {
      setDraft(formatNumberDraft(value, hexDigits));
    }
  }, [value, allowHex, hexDigits]);

  const docId = `${id}-doc`;
  const describedBy = joinDescribedBy(getFeedbackId(id, error, warning), doc && infoOpen ? docId : undefined);

  return (
    <div
      className={`field${isHighlighted ? ' is-highlighted' : ''}`}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <div className="field-label-row">
        <div className="field-label-main">
          <label className="field-label" htmlFor={id}>
            {label}
          </label>
          {doc && (
            <FieldInfoButton
              label={label}
              docId={docId}
              open={infoOpen}
              onToggle={() => setInfoOpen((prev) => !prev)}
              onClose={() => setInfoOpen(false)}
              onFocus={onHoverStart}
              onBlur={onHoverEnd}
            />
          )}
        </div>
        {hint && <span className="field-hint">{hint}</span>}
      </div>
      <input
        id={id}
        type="text"
        inputMode={allowHex ? 'text' : 'numeric'}
        className={`field-input mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
        value={draft}
        placeholder={placeholder}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        onFocus={onHoverStart}
        onBlur={onHoverEnd}
        onChange={(e) => {
          const nextRaw = e.target.value;
          setDraft(nextRaw);
          onChange(parseUnsignedIntInput(nextRaw, allowHex));
        }}
      />
      {doc && infoOpen && <FieldDocBox id={docId} doc={doc} />}
      <FieldFeedback id={id} error={error} warning={warning} />
    </div>
  );
}

export interface AutoManualFieldProps extends BaseFieldProps {
  readonly value: AutoOrManual<number>;
  readonly resolvedAutoValue?: number;
  readonly allowHex?: boolean;
  readonly hexDigits?: number;
  readonly onChange: (next: AutoOrManual<number>) => void;
}

export function AutoManualField({
  id,
  label,
  hint,
  doc,
  error,
  warning,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
  value,
  resolvedAutoValue,
  allowHex = false,
  hexDigits,
  onChange,
}: AutoManualFieldProps) {
  const [draft, setDraft] = useState<string>(() =>
    value.mode === 'manual' ? formatNumberDraft(value.value, hexDigits) : '',
  );
  const [infoOpen, setInfoOpen] = useState(false);

  useEffect(() => {
    if (value.mode !== 'manual') {
      return;
    }
    const parsedDraft = parseUnsignedIntInput(draft, allowHex);
    if (!Number.isNaN(value.value) && parsedDraft !== value.value) {
      setDraft(formatNumberDraft(value.value, hexDigits));
    }
  }, [value, allowHex, hexDigits]);

  const isAuto = value.mode === 'auto';
  const docId = `${id}-doc`;
  const describedBy = joinDescribedBy(getFeedbackId(id, error, warning), doc && infoOpen ? docId : undefined);
  const autoLabelId = `${id}-label`;

  const autoDisplayText =
    resolvedAutoValue === undefined
      ? 'Pending'
      : hexDigits
        ? `${formatHex(resolvedAutoValue, hexDigits)} (${resolvedAutoValue})`
        : String(resolvedAutoValue);

  const handleSwitchMode = (mode: 'auto' | 'manual') => {
    if (mode === 'auto') {
      onChange(autoValue());
    } else {
      const seed = resolvedAutoValue ?? 0;
      setDraft(formatNumberDraft(seed, hexDigits));
      onChange(manualValue(seed));
    }
  };

  return (
    <div
      className={`field${isHighlighted ? ' is-highlighted' : ''}`}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <div className="field-label-row">
        <div className="field-label-main">
          {isAuto ? (
            <span id={autoLabelId} className="field-label">
              {label}
            </span>
          ) : (
            <label className="field-label" htmlFor={id}>
              {label}
            </label>
          )}
          {doc && (
            <FieldInfoButton
              label={label}
              docId={docId}
              open={infoOpen}
              onToggle={() => setInfoOpen((prev) => !prev)}
              onClose={() => setInfoOpen(false)}
              onFocus={onHoverStart}
              onBlur={onHoverEnd}
            />
          )}
        </div>
        <div className="mode-toggle" role="group" aria-label={`${label} mode`}>
          <button
            type="button"
            className={`mode-btn${isAuto ? ' is-active' : ''}`}
            aria-pressed={isAuto}
            onClick={() => handleSwitchMode('auto')}
          >
            Auto
          </button>
          <button
            type="button"
            className={`mode-btn${!isAuto ? ' is-active' : ''}`}
            aria-pressed={!isAuto}
            onClick={() => handleSwitchMode('manual')}
          >
            Manual
          </button>
        </div>
      </div>

      {isAuto ? (
        <div
          className={`field-auto-preview mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
          role="group"
          aria-labelledby={autoLabelId}
          aria-describedby={describedBy}
        >
          <span className="auto-tag">AUTO</span>
          <span className="auto-val">{autoDisplayText}</span>
          {hint && <span className="auto-hint">{hint}</span>}
        </div>
      ) : (
        <input
          id={id}
          type="text"
          inputMode={allowHex ? 'text' : 'numeric'}
          className={`field-input mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
          value={draft}
          placeholder={hint}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          onFocus={onHoverStart}
          onBlur={onHoverEnd}
          onChange={(e) => {
            const nextRaw = e.target.value;
            setDraft(nextRaw);
            onChange(manualValue(parseUnsignedIntInput(nextRaw, allowHex)));
          }}
        />
      )}

      {doc && infoOpen && <FieldDocBox id={docId} doc={doc} />}
      <FieldFeedback id={id} error={error} warning={warning} />
    </div>
  );
}

export interface AutoManualTextFieldProps extends BaseFieldProps {
  readonly value: AutoOrManual<string>;
  readonly autoPreviewText: string;
  readonly manualSeedValue: string;
  readonly placeholder?: string;
  readonly fullWidth?: boolean;
  readonly onChange: (next: AutoOrManual<string>) => void;
}

export function AutoManualTextField({
  id,
  label,
  hint,
  doc,
  error,
  warning,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
  value,
  autoPreviewText,
  manualSeedValue,
  placeholder,
  fullWidth = false,
  onChange,
}: AutoManualTextFieldProps) {
  const [infoOpen, setInfoOpen] = useState(false);
  const isAuto = value.mode === 'auto';
  const docId = `${id}-doc`;
  const describedBy = joinDescribedBy(getFeedbackId(id, error, warning), doc && infoOpen ? docId : undefined);
  const autoLabelId = `${id}-label`;

  const handleSwitchMode = (mode: 'auto' | 'manual') => {
    if (mode === 'auto') {
      onChange(autoValue<string>());
    } else {
      onChange(manualValue(manualSeedValue));
    }
  };

  return (
    <div
      className={`field${fullWidth ? ' field-span-full' : ''}${isHighlighted ? ' is-highlighted' : ''}`}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <div className="field-label-row">
        <div className="field-label-main">
          {isAuto ? (
            <span id={autoLabelId} className="field-label">
              {label}
            </span>
          ) : (
            <label className="field-label" htmlFor={id}>
              {label}
            </label>
          )}
          {doc && (
            <FieldInfoButton
              label={label}
              docId={docId}
              open={infoOpen}
              onToggle={() => setInfoOpen((prev) => !prev)}
              onClose={() => setInfoOpen(false)}
              onFocus={onHoverStart}
              onBlur={onHoverEnd}
            />
          )}
        </div>
        <div className="mode-toggle" role="group" aria-label={`${label} mode`}>
          <button
            type="button"
            className={`mode-btn${isAuto ? ' is-active' : ''}`}
            aria-pressed={isAuto}
            onClick={() => handleSwitchMode('auto')}
          >
            Auto
          </button>
          <button
            type="button"
            className={`mode-btn${!isAuto ? ' is-active' : ''}`}
            aria-pressed={!isAuto}
            onClick={() => handleSwitchMode('manual')}
          >
            Manual
          </button>
        </div>
      </div>

      {isAuto ? (
        <div
          className={`field-auto-preview mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
          role="group"
          aria-labelledby={autoLabelId}
          aria-describedby={describedBy}
        >
          <span className="auto-tag">AUTO</span>
          <span className="auto-val">{autoPreviewText}</span>
          {hint && <span className="auto-hint">{hint}</span>}
        </div>
      ) : (
        <input
          id={id}
          type="text"
          className={`field-input mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
          value={value.value}
          placeholder={placeholder ?? hint}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          onFocus={onHoverStart}
          onBlur={onHoverEnd}
          onChange={(e) => onChange(manualValue(e.target.value))}
        />
      )}

      {doc && infoOpen && <FieldDocBox id={docId} doc={doc} />}
      <FieldFeedback id={id} error={error} warning={warning} />
    </div>
  );
}
