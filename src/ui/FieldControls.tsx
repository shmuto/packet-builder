import { useEffect, useState } from 'react';
import { formatHex, parseUnsignedIntInput } from '../core/inspector';
import { autoValue, manualValue, type AutoOrManual } from '../core/layers/types';

interface BaseFieldProps {
  readonly id: string;
  readonly label: string;
  readonly hint?: string;
  readonly error?: string;
  readonly warning?: string;
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
  value,
  placeholder,
  onChange,
}: TextFieldProps) {
  const feedbackId = getFeedbackId(id, error, warning);

  return (
    <div className="field">
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

/**
 * 数値入力欄。入力途中の空文字や不正文字でも状態を壊さず保持し、
 * parseUnsignedIntInput の結果（不正時は NaN）を親へ渡して core 側で検証させる。
 */
export function NumberField({
  id,
  label,
  hint,
  error,
  warning,
  value,
  allowHex = false,
  hexDigits,
  placeholder,
  onChange,
}: NumberFieldProps) {
  const [draft, setDraft] = useState<string>(() => formatNumberDraft(value, hexDigits));

  // プリセット切替など外部から value が更新された場合にドラフトを同期する
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
    <div className="field">
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
  /** core が計算した自動値（エラー時は undefined） */
  readonly resolvedAutoValue?: number;
  readonly allowHex?: boolean;
  readonly hexDigits?: number;
  readonly onChange: (next: AutoOrManual<number>) => void;
}

/**
 * 「自動（計算値プレビュー）」と「手動（任意値入力）」を切り替えられるフィールド。
 */
export function AutoManualField({
  id,
  label,
  hint,
  error,
  warning,
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
      ? '計算待ち'
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
    <div className="field">
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
        <div className="mode-toggle" role="group" aria-label={`${label} の計算モード`}>
          <button
            type="button"
            className={`mode-btn${isAuto ? ' is-active' : ''}`}
            aria-pressed={isAuto}
            onClick={() => handleSwitchMode('auto')}
          >
            自動
          </button>
          <button
            type="button"
            className={`mode-btn${!isAuto ? ' is-active' : ''}`}
            aria-pressed={!isAuto}
            onClick={() => handleSwitchMode('manual')}
          >
            手動
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
