import { useMemo, useState } from 'react';
import { decodeBgpHex } from '../../core/bgp';
import { toHexString } from '../../core/bytes';
import { BgpMessageInspector } from './BgpMessageInspector';

const SAMPLE_OPEN_AND_KEEPALIVE_HEX =
  'ffffffffffffffffffffffffffffffff003301045ba0005ac0000201160214010400010001010400020001020041040001000f' +
  'ffffffffffffffffffffffffffffffff001304';

export interface DecodeBgpHexPanelProps {
  readonly onClose: () => void;
}

export function DecodeBgpHexPanel({ onClose }: DecodeBgpHexPanelProps) {
  const [hexInput, setHexInput] = useState(SAMPLE_OPEN_AND_KEEPALIVE_HEX);
  const [fourOctetAs, setFourOctetAs] = useState(true);
  const [selectedMsgIndex, setSelectedMsgIndex] = useState(0);

  const decoded = useMemo(
    () => decodeBgpHex(hexInput, { fourOctetAs }),
    [hexInput, fourOctetAs],
  );

  const activeIdx =
    selectedMsgIndex < decoded.messages.length ? selectedMsgIndex : 0;
  const activeMsg = decoded.messages[activeIdx];

  return (
    <section className="bgp-panel bgp-hex-decoder-panel" aria-label="Decode BGP Hex">
      <div className="bgp-panel-header">
        <div>
          <h2 className="bgp-panel-title">Decode BGP Hex</h2>
          <p className="bgp-panel-subtitle">
            Paste one or more raw BGP messages (starting with the 16-byte 0xff Marker) from router logs, captures, or NOTIFICATION data.
          </p>
        </div>
        <button type="button" className="bgp-mini-btn" onClick={onClose}>
          Back to Session
        </button>
      </div>

      <div className="bgp-decoder-controls">
        <label className="bgp-toggle-label">
          <input
            type="checkbox"
            checked={fourOctetAs}
            onChange={(e) => setFourOctetAs(e.target.checked)}
          />
          <span>4-octet AS in effect (RFC 6793 — 4-byte AS_PATH / AGGREGATOR)</span>
        </label>
        <button
          type="button"
          className="bgp-mini-btn"
          onClick={() => {
            setHexInput(SAMPLE_OPEN_AND_KEEPALIVE_HEX);
            setSelectedMsgIndex(0);
          }}
        >
          Load Sample
        </button>
      </div>

      <textarea
        className="bgp-hex-textarea mono"
        rows={4}
        aria-label="Raw BGP hexadecimal bytes"
        placeholder="Paste raw BGP hex (continuous, spaced, or Wireshark hex dump)..."
        value={hexInput}
        onChange={(e) => {
          setHexInput(e.target.value);
          setSelectedMsgIndex(0);
        }}
      />

      {decoded.notes.length > 0 && (
        <div className="bgp-omissions-box" role="status">
          <h3 className="bgp-omissions-title">Decoder notes</h3>
          <ul className="bgp-omissions-list">
            {decoded.notes.map((note, idx) => (
              <li key={idx}>{note}</li>
            ))}
          </ul>
          {decoded.unparsedBytes.length > 0 && (
            <p className="mono bgp-unparsed-hex">
              Unparsed ({decoded.unparsedBytes.length} B at offset {decoded.unparsedOffset}):{' '}
              {toHexString(decoded.unparsedBytes)}
            </p>
          )}
        </div>
      )}

      {decoded.messages.length > 1 && (
        <div className="bgp-decoded-tabs" role="tablist" aria-label="Decoded BGP messages">
          {decoded.messages.map((m, idx) => (
            <button
              key={idx}
              type="button"
              role="tab"
              aria-selected={idx === activeIdx}
              className={`bgp-tab-btn${idx === activeIdx ? ' is-active' : ''}`}
              onClick={() => setSelectedMsgIndex(idx)}
            >
              #{idx + 1} {m.message.type.toUpperCase()} ({m.bytes.length} B)
            </button>
          ))}
        </div>
      )}

      {activeMsg && (
        <BgpMessageInspector
          title={`Message #${activeIdx + 1}: ${activeMsg.tree.label}`}
          subtitle={`Stream offset ${activeMsg.offset} · ${activeMsg.bytes.length} bytes · ${fourOctetAs ? '4-octet AS' : '2-octet AS'}`}
          bgpBytes={activeMsg.bytes}
          tree={activeMsg.tree}
          explanations={activeMsg.notes}
        />
      )}
    </section>
  );
}
