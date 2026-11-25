export type PayloadMode = 'text' | 'hex';

export interface PayloadCardProps {
  readonly mode: PayloadMode;
  readonly textValue: string;
  readonly hexValue: string;
  readonly byteLength: number;
  readonly error?: string;
  readonly modeSwitchError?: string;
  readonly isHighlighted?: boolean;
  readonly onHoverStart?: () => void;
  readonly onHoverEnd?: () => void;
  readonly onModeChange: (mode: PayloadMode) => void;
  readonly onTextChange: (next: string) => void;
  readonly onHexChange: (next: string) => void;
}

export function PayloadCard({
  mode,
  textValue,
  hexValue,
  byteLength,
  error,
  modeSwitchError,
  isHighlighted = false,
  onHoverStart,
  onHoverEnd,
  onModeChange,
  onTextChange,
  onHexChange,
}: PayloadCardProps) {
  const describedByIds = [
    error ? 'payload-hex-error' : null,
    modeSwitchError ? 'payload-mode-switch-error' : null,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <section
      className={`layer-card layer-theme-payload${error ? ' has-error' : ''}${isHighlighted ? ' is-highlighted-card' : ''}`}
      aria-label="Payload editor"
      onMouseEnter={onHoverStart}
      onMouseLeave={onHoverEnd}
    >
      <header className="layer-header">
        <div className="layer-title-static">
          <span className="layer-osi">DATA</span>
          <span className="layer-name">Payload</span>
          <span className="layer-rfc mono">{byteLength} bytes</span>
        </div>

        <div className="mode-toggle" role="group" aria-label="Payload input format">
          <button
            type="button"
            className={`mode-btn${mode === 'text' ? ' is-active' : ''}`}
            aria-pressed={mode === 'text'}
            onClick={() => onModeChange('text')}
          >
            Text (UTF-8)
          </button>
          <button
            type="button"
            className={`mode-btn${mode === 'hex' ? ' is-active' : ''}`}
            aria-pressed={mode === 'hex'}
            onClick={() => onModeChange('hex')}
          >
            Hex
          </button>
        </div>
      </header>

      <div className="layer-body">
        {mode === 'text' ? (
          <div className={`field${isHighlighted ? ' is-highlighted' : ''}`}>
            <label className="sr-only" htmlFor="payload-text-input">
              Payload text (UTF-8)
            </label>
            <textarea
              id="payload-text-input"
              className="field-textarea mono"
              rows={3}
              placeholder="Enter payload text (leave empty for 0 bytes)"
              value={textValue}
              onFocus={onHoverStart}
              onBlur={onHoverEnd}
              onChange={(e) => onTextChange(e.target.value)}
            />
          </div>
        ) : (
          <div className={`field${isHighlighted ? ' is-highlighted' : ''}`}>
            <label className="sr-only" htmlFor="payload-hex-input">
              Payload hex bytes
            </label>
            <textarea
              id="payload-hex-input"
              className={`field-textarea mono${error ? ' is-error' : ''}`}
              rows={3}
              placeholder="e.g. 48 65 6c 6c 6f (whitespace allowed)"
              value={hexValue}
              aria-invalid={error ? true : undefined}
              aria-describedby={describedByIds || undefined}
              onFocus={onHoverStart}
              onBlur={onHoverEnd}
              onChange={(e) => onHexChange(e.target.value)}
            />
            {error && (
              <p id="payload-hex-error" className="field-msg is-error" role="alert">
                {error}
              </p>
            )}
            {modeSwitchError && (
              <p id="payload-mode-switch-error" className="field-msg is-warning" role="alert">
                {modeSwitchError}
              </p>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
