import { useEffect, useState } from 'react';
import { formatHex, parseUnsignedIntInput } from '../core/inspector';
import { autoValue, manualValue, type AutoOrManual } from '../core/layers/types';

interface BaseFieldProps {
  readonly id: string;
  readonly label: string;
  readonly hint?: string;
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
  readonly label: string;
  readonly value: string;
  readonly bits: string;
  readonly isHighlighted?: boolean;
  readonly onHoverStart?: () => void;
  readonly onHoverEnd?: () => void;
}

/** Read-only fixed header field chip (e.g., IPv4 Version=4, IHL=5, TCP Reserved=0) with hover sync */
export function FixedFieldChip({
  label,
  value,
  bits,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
}: FixedFieldChipProps) {
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

export interface TextFieldProps extends BaseFieldProps {
  readonly value: string;
  readonly placeholder?: string;
  readonly onChange: (next: string) => void;
}

export function TextField({
  id,
  label,
  hint,
  error,
  warning,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
  value,
  placeholder,
  onChange,
}: TextFieldProps) {
  const feedbackId = getFeedbackId(id, error, warning);

  return (
    <div
      className={`field${isHighlighted ? ' is-highlighted' : ''}`}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <div className="field-label-row">
        <label className="field-label" htmlFor={id}>
          {label}
        </label>
        {hint && <span className="field-hint">{hint}</span>}
      </div>
      <input
        id={id}
        type="text"
        className={`field-input mono${error ? ' is-error' : warning ? ' is-warning' : ''}`}
        value={value}
        placeholder={placeholder}
        aria-invalid={error ? true : undefined}
        aria-describedby={feedbackId}
        onFocus={onHoverStart}
        onBlur={onHoverEnd}
        onChange={(e) => onChange(e.target.value)}
      />
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

  useEffect(() => {
    const parsedDraft = parseUnsignedIntInput(draft, allowHex);
    if (Number.isNaN(value)) {
      return;
    }
    if (parsedDraft !== value) {
      setDraft(formatNumberDraft(value, hexDigits));
    }
  }, [value, allowHex, hexDigits]);

  const feedbackId = getFeedbackId(id, error, warning);

  return (
    <div
      className={`field${isHighlighted ? ' is-highlighted' : ''}`}
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <div className="field-label-row">
        <label className="field-label" htmlFor={id}>
          {label}
        </label>
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
        aria-describedby={feedbackId}
        onFocus={onHoverStart}
        onBlur={onHoverEnd}
        onChange={(e) => {
          const nextRaw = e.target.value;
          setDraft(nextRaw);
          onChange(parseUnsignedIntInput(nextRaw, allowHex));
        }}
      />
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
  const feedbackId = getFeedbackId(id, error, warning);
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
        {isAuto ? (
          <span id={autoLabelId} className="field-label">
            {label}
          </span>
        ) : (
          <label className="field-label" htmlFor={id}>
            {label}
          </label>
        )}
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
          aria-describedby={feedbackId}
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
          aria-describedby={feedbackId}
          onFocus={onHoverStart}
          onBlur={onHoverEnd}
          onChange={(e) => {
            const nextRaw = e.target.value;
            setDraft(nextRaw);
            onChange(manualValue(parseUnsignedIntInput(nextRaw, allowHex)));
          }}
        />
      )}

      <FieldFeedback id={id} error={error} warning={warning} />
    </div>
  );
}
