import { useState } from 'react';
import { parseHexOrDump } from '../core/bytes';
import {
  decodePacket,
  type DecodedPacket,
  type DecodeStartLayer,
} from '../core/decode';

export interface ImportHexPanelProps {
  readonly onImport: (decoded: DecodedPacket) => void;
  readonly onClose: () => void;
}

export function ImportHexPanel({ onImport, onClose }: ImportHexPanelProps) {
  const [startLayer, setStartLayer] = useState<DecodeStartLayer>('ethernet');
  const [rawInput, setRawInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleDecode = () => {
    const parsed = parseHexOrDump(rawInput);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    const decoded = decodePacket(parsed.value, startLayer);
    if (!decoded.ok) {
      setError(decoded.error);
      return;
    }
    setError(null);
    onImport(decoded.value);
  };

  return (
    <section className="import-panel" aria-label="Import packet from hex">
      <div className="import-panel-header">
        <div>
          <h2 className="import-panel-title">Import Packet from Hex</h2>
          <p className="import-panel-sub">
            Paste a raw hex stream or offset-prefixed hex dump (e.g., from Copy Hex, Copy Dump, or Wireshark).
          </p>
        </div>
        <button
          type="button"
          className="icon-btn"
          aria-label="Close import panel"
          onClick={onClose}
        >
          ✕
        </button>
      </div>

      <div className="import-controls-row">
        <span className="field-label">Outermost layer</span>
        <div className="mode-toggle" role="group" aria-label="Outermost layer type">
          <button
            type="button"
            className={`mode-btn${startLayer === 'ethernet' ? ' is-active' : ''}`}
            aria-pressed={startLayer === 'ethernet'}
            onClick={() => setStartLayer('ethernet')}
          >
            Ethernet II Frame
          </button>
          <button
            type="button"
            className={`mode-btn${startLayer === 'ipv4' ? ' is-active' : ''}`}
            aria-pressed={startLayer === 'ipv4'}
            onClick={() => setStartLayer('ipv4')}
          >
            Raw IPv4 Packet
          </button>
        </div>
      </div>

      <div className="field">
        <label className="sr-only" htmlFor="import-hex-textarea">
          Hexadecimal packet bytes
        </label>
        <textarea
          id="import-hex-textarea"
          className={`field-textarea mono${error ? ' is-error' : ''}`}
          rows={4}
          placeholder="e.g. 00112233445566778899aabb08004500... or 0000: 00 11 22 33 ..."
          value={rawInput}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? 'import-hex-error' : undefined}
          onChange={(e) => {
            setRawInput(e.target.value);
            if (error) setError(null);
          }}
        />
        {error && (
          <p id="import-hex-error" className="field-msg is-error" role="alert">
            {error}
          </p>
        )}
      </div>

      <div className="import-actions">
        <button type="button" className="export-btn is-primary" onClick={handleDecode}>
          Decode &amp; Load
        </button>
        <button type="button" className="export-btn" onClick={onClose}>
          Cancel
        </button>
      </div>
    </section>
  );
}
