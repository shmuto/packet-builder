import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { decodeUtf8Strict, encodeUtf8, parseHexBytes } from './core/bytes';
import { detectPrintableUtf8, type DecodedPacket } from './core/decode';
import {
  evaluatePacketDraft,
  formatSpacedHex,
  isFieldHighlighted,
  type HighlightTarget,
} from './core/inspector';
import type { Layer, LayerType } from './core/layers/types';
import {
  buildPermalinkUrl,
  decodePermalink,
  encodePermalink,
  hasOnlyFiniteNumbers,
  type PermalinkState,
} from './core/permalink';
import { createPresets, type PacketPreset, type PresetId } from './core/presets';
import { ok, type Result } from './core/result';
import { analyzeDecodeRoundTrip, type RoundTripReport } from './core/roundtrip';
import { HexDumpInspector } from './ui/HexDumpInspector';
import { ImportHexPanel } from './ui/ImportHexPanel';
import { LayerCard } from './ui/LayerCard';
import { ADDABLE_LAYER_TYPES, createLayerByType, LAYER_META } from './ui/layerMeta';
import { PayloadCard, type PayloadMode } from './ui/PayloadCard';

interface LayerItem {
  readonly id: string;
  readonly layer: Layer;
}

interface EditorFields {
  readonly activePresetId: PresetId | null;
  readonly layers: readonly Layer[];
  readonly payloadMode: PayloadMode;
  readonly payloadText: string;
  readonly payloadHex: string;
}

interface InitialEditorState extends EditorFields {
  readonly permalinkError: string | null;
  readonly initialSyncedFragment: string | null;
  readonly suppressInitialSync: boolean;
}

const HASH_SYNC_DEBOUNCE_MS = 250;

function fieldsFromPreset(preset: PacketPreset): EditorFields {
  return {
    activePresetId: preset.id,
    layers: preset.layers,
    payloadMode: 'text',
    payloadText: preset.payloadText,
    payloadHex: formatSpacedHex(preset.payloadBytes),
  };
}

function fieldsFromPermalink(state: PermalinkState): EditorFields {
  const { layers, payload } = state;
  return {
    activePresetId: null,
    layers,
    payloadMode: payload.mode,
    payloadText: payload.mode === 'text' ? payload.text : '',
    payloadHex:
      payload.mode === 'hex' ? payload.hex : formatSpacedHex(encodeUtf8(payload.text)),
  };
}

function readInitialEditorState(defaultPreset: PacketPreset): InitialEditorState {
  const fallback = (permalinkError: string | null): InitialEditorState => ({
    ...fieldsFromPreset(defaultPreset),
    permalinkError,
    initialSyncedFragment: null,
    suppressInitialSync: true,
  });

  if (typeof window === 'undefined') {
    return fallback(null);
  }

  const hash = window.location.hash;
  if (hash.length === 0 || hash === '#') {
    return fallback(null);
  }

  const decoded = decodePermalink(hash);
  if (!decoded.ok) {
    return fallback(`Could not load packet from URL: ${decoded.error}`);
  }

  return {
    ...fieldsFromPermalink(decoded.value),
    permalinkError: null,
    initialSyncedFragment: encodePermalink(decoded.value),
    suppressInitialSync: false,
  };
}

export function App() {
  const presets = useMemo(() => createPresets(), []);
  const nextIdRef = useRef(1);
  const allocateId = useCallback(() => `layer-${nextIdRef.current++}`, []);

  const initialStateRef = useRef<InitialEditorState | null>(null);
  if (initialStateRef.current === null) {
    initialStateRef.current = readInitialEditorState(presets[0]);
  }
  const initialState = initialStateRef.current;

  const [activePresetId, setActivePresetId] = useState<PresetId | null>(
    initialState.activePresetId,
  );
  const [layerItems, setLayerItems] = useState<LayerItem[]>(() =>
    initialState.layers.map((layer) => ({ id: allocateId(), layer })),
  );
  const [payloadMode, setPayloadMode] = useState<PayloadMode>(initialState.payloadMode);
  const [payloadText, setPayloadText] = useState<string>(initialState.payloadText);
  const [payloadHex, setPayloadHex] = useState<string>(initialState.payloadHex);
  const [payloadModeSwitchError, setPayloadModeSwitchError] = useState<string | undefined>(
    undefined,
  );
  const [highlight, setHighlight] = useState<HighlightTarget | null>(null);
  const [showImportPanel, setShowImportPanel] = useState(false);
  const [importNotes, setImportNotes] = useState<readonly string[]>([]);
  const [permalinkError, setPermalinkError] = useState<string | null>(
    initialState.permalinkError,
  );

  const lastSyncedFragmentRef = useRef<string | null>(initialState.initialSyncedFragment);
  const suppressSyncRef = useRef<boolean>(initialState.suppressInitialSync);
  const pendingFragmentRef = useRef<string | null>(null);
  const hashSyncTimerRef = useRef<number | null>(null);

  const payloadResult: Result<Uint8Array> = useMemo(() => {
    if (payloadMode === 'text') {
      return ok(encodeUtf8(payloadText));
    }
    return parseHexBytes(payloadHex);
  }, [payloadMode, payloadText, payloadHex]);

  const layers = useMemo(() => layerItems.map((item) => item.layer), [layerItems]);

  const draft = useMemo(
    () => evaluatePacketDraft(layers, payloadResult),
    [layers, payloadResult],
  );

  const roundTripReport: RoundTripReport = useMemo(() => {
    if (!payloadResult.ok) {
      return { kind: 'not-built' };
    }
    return analyzeDecodeRoundTrip(layers, payloadResult.value);
  }, [layers, payloadResult]);

  const permalinkState: PermalinkState = useMemo(
    () => ({
      layers,
      payload:
        payloadMode === 'text'
          ? { mode: 'text', text: payloadText }
          : { mode: 'hex', hex: payloadHex },
    }),
    [layers, payloadMode, payloadText, payloadHex],
  );

  const permalinkFragment: string | null = useMemo(() => {
    if (!hasOnlyFiniteNumbers(layers)) {
      return null;
    }
    return encodePermalink(permalinkState);
  }, [layers, permalinkState]);

  const permalinkUrl: string | null = useMemo(() => {
    if (permalinkFragment === null || typeof window === 'undefined') {
      return null;
    }
    return buildPermalinkUrl(
      window.location.origin,
      window.location.pathname,
      permalinkFragment,
    );
  }, [permalinkFragment]);

  const flushPendingHashSync = useCallback(() => {
    if (hashSyncTimerRef.current !== null) {
      window.clearTimeout(hashSyncTimerRef.current);
      hashSyncTimerRef.current = null;
    }
    const pending = pendingFragmentRef.current;
    pendingFragmentRef.current = null;
    if (pending !== null && pending !== lastSyncedFragmentRef.current) {
      window.history.replaceState(null, '', `#${pending}`);
      lastSyncedFragmentRef.current = pending;
    }
  }, []);

  // Keep URL hash in sync with editor state using debounced history.replaceState
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (suppressSyncRef.current || permalinkFragment === null) {
      pendingFragmentRef.current = null;
      return;
    }
    if (permalinkFragment === lastSyncedFragmentRef.current) {
      pendingFragmentRef.current = null;
      return;
    }

    pendingFragmentRef.current = permalinkFragment;
    if (hashSyncTimerRef.current !== null) {
      window.clearTimeout(hashSyncTimerRef.current);
    }

    hashSyncTimerRef.current = window.setTimeout(flushPendingHashSync, HASH_SYNC_DEBOUNCE_MS);

    return () => {
      if (hashSyncTimerRef.current !== null) {
        window.clearTimeout(hashSyncTimerRef.current);
        hashSyncTimerRef.current = null;
      }
    };
  }, [permalinkFragment, flushPendingHashSync]);

  // Flush any pending debounced hash update before reload/navigation so recent edits are never lost
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.addEventListener('pagehide', flushPendingHashSync);
    window.addEventListener('beforeunload', flushPendingHashSync);
    return () => {
      window.removeEventListener('pagehide', flushPendingHashSync);
      window.removeEventListener('beforeunload', flushPendingHashSync);
    };
  }, [flushPendingHashSync]);

  const applyEditorFields = useCallback(
    (fields: EditorFields, error: string | null) => {
      setActivePresetId(fields.activePresetId);
      setLayerItems(fields.layers.map((layer) => ({ id: allocateId(), layer })));
      setPayloadMode(fields.payloadMode);
      setPayloadText(fields.payloadText);
      setPayloadHex(fields.payloadHex);
      setPayloadModeSwitchError(undefined);
      setImportNotes([]);
      setPermalinkError(error);
      setHighlight(null);
    },
    [allocateId],
  );

  // Listen for hashchange events (e.g., user edits URL fragment or navigates history)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const resetToDefaultPreset = (error: string | null) => {
      suppressSyncRef.current = true;
      lastSyncedFragmentRef.current = null;
      applyEditorFields(fieldsFromPreset(presets[0]), error);
    };

    const handleHashChange = () => {
      pendingFragmentRef.current = null;
      if (hashSyncTimerRef.current !== null) {
        window.clearTimeout(hashSyncTimerRef.current);
        hashSyncTimerRef.current = null;
      }

      const hash = window.location.hash;
      if (hash.length === 0 || hash === '#') {
        resetToDefaultPreset(null);
        return;
      }

      const decoded = decodePermalink(hash);
      if (!decoded.ok) {
        resetToDefaultPreset(`Could not load packet from URL: ${decoded.error}`);
        return;
      }

      suppressSyncRef.current = false;
      lastSyncedFragmentRef.current = encodePermalink(decoded.value);
      applyEditorFields(fieldsFromPermalink(decoded.value), null);
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [applyEditorFields, presets]);

  const markUserEdited = () => {
    suppressSyncRef.current = false;
    setPermalinkError(null);
  };

  const applyPreset = (preset: PacketPreset) => {
    markUserEdited();
    applyEditorFields(fieldsFromPreset(preset), null);
  };

  const handleImportDecoded = (decoded: DecodedPacket) => {
    markUserEdited();
    setActivePresetId(null);
    setLayerItems(decoded.layers.map((layer) => ({ id: allocateId(), layer })));
    const textCheck = detectPrintableUtf8(decoded.payload);
    if (textCheck.printable) {
      setPayloadMode('text');
      setPayloadText(textCheck.text);
      setPayloadHex(formatSpacedHex(decoded.payload));
    } else {
      setPayloadMode('hex');
      setPayloadText('');
      setPayloadHex(formatSpacedHex(decoded.payload));
    }
    setPayloadModeSwitchError(undefined);
    setImportNotes(decoded.notes);
    setHighlight(null);
    setShowImportPanel(false);
  };

  const handleLayerChange = (index: number, nextLayer: Layer) => {
    markUserEdited();
    setActivePresetId(null);
    setImportNotes([]);
    setLayerItems((prev) =>
      prev.map((item, i) => (i === index ? { ...item, layer: nextLayer } : item)),
    );
  };

  const handleMoveLayer = (index: number, delta: -1 | 1) => {
    const targetIndex = index + delta;
    if (targetIndex < 0 || targetIndex >= layerItems.length) {
      return;
    }
    markUserEdited();
    setActivePresetId(null);
    setImportNotes([]);
    setHighlight(null);
    setLayerItems((prev) => {
      const copy = [...prev];
      const [moved] = copy.splice(index, 1);
      copy.splice(targetIndex, 0, moved);
      return copy;
    });
  };

  const handleRemoveLayer = (index: number) => {
    markUserEdited();
    setActivePresetId(null);
    setImportNotes([]);
    setHighlight(null);
    setLayerItems((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAddLayer = (type: LayerType) => {
    markUserEdited();
    setActivePresetId(null);
    setImportNotes([]);
    setHighlight(null);
    setLayerItems((prev) => [...prev, { id: allocateId(), layer: createLayerByType(type) }]);
  };

  const handlePayloadModeChange = (nextMode: PayloadMode) => {
    if (nextMode === payloadMode) return;

    if (nextMode === 'hex') {
      markUserEdited();
      setPayloadHex(formatSpacedHex(encodeUtf8(payloadText)));
      setPayloadModeSwitchError(undefined);
      setPayloadMode('hex');
      return;
    }

    const parsed = parseHexBytes(payloadHex);
    if (!parsed.ok) {
      setPayloadModeSwitchError(
        `Cannot switch to Text mode while hex input is invalid (${parsed.error})`,
      );
      return;
    }
    const decoded = decodeUtf8Strict(parsed.value);
    if (!decoded.ok) {
      setPayloadModeSwitchError(
        `${decoded.error} Edit the hex bytes before switching to Text mode.`,
      );
      return;
    }
    markUserEdited();
    setPayloadText(decoded.value);
    setPayloadModeSwitchError(undefined);
    setPayloadMode('text');
  };

  const payloadLayerIndex = layers.length;
  const isPayloadHighlighted = isFieldHighlighted(
    payloadLayerIndex,
    'payload',
    draft.spans,
    highlight,
  );

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <div className="brand-title-row">
            <h1 className="brand-title">tsumiki</h1>
            <span className="brand-sub">packet builder</span>
          </div>
          <p className="brand-desc">
            Stack Ethernet II, ARP, IPv4, ICMP, UDP, TCP, and BGP-4 layers like building blocks to inspect, decode, and export raw network packets.
          </p>
        </div>

        <nav className="preset-bar" aria-label="Packet presets and import">
          <span className="preset-label">Presets</span>
          <div className="preset-list">
            {presets.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className={`preset-btn${activePresetId === preset.id ? ' is-active' : ''}`}
                title={preset.description}
                aria-pressed={activePresetId === preset.id}
                onClick={() => applyPreset(preset)}
              >
                {preset.name}
              </button>
            ))}
            <button
              type="button"
              className={`preset-btn is-import${showImportPanel ? ' is-active' : ''}`}
              aria-expanded={showImportPanel}
              onClick={() => setShowImportPanel((open) => !open)}
            >
              Import Hex
            </button>
          </div>
        </nav>
      </header>

      {permalinkError && (
        <div className="permalink-error-banner" role="alert">
          <div className="import-notes-body">
            <strong>Invalid Permalink</strong>
            <span>{permalinkError} Loaded the default preset instead.</span>
          </div>
          <button
            type="button"
            className="icon-btn"
            aria-label="Dismiss permalink error"
            onClick={() => setPermalinkError(null)}
          >
            ✕
          </button>
        </div>
      )}

      {showImportPanel && (
        <ImportHexPanel
          onImport={handleImportDecoded}
          onClose={() => setShowImportPanel(false)}
        />
      )}

      {importNotes.length > 0 && (
        <div className="import-notes-banner" role="status">
          <div className="import-notes-body">
            <strong>Import Notes:</strong>
            <ul className="inspector-msg-list">
              {importNotes.map((note, i) => (
                <li key={i}>{note}</li>
              ))}
            </ul>
          </div>
          <button
            type="button"
            className="icon-btn"
            aria-label="Dismiss import notes"
            onClick={() => setImportNotes([])}
          >
            ✕
          </button>
        </div>
      )}

      <main className="workbench">
        <section className="stack-column" aria-label="Layer stack editor">
          <div className="stack-toolbar">
            <h2 className="section-heading">Layer Stack (outer to inner)</h2>
            <div className="add-layer-bar" role="group" aria-label="Add protocol layer">
              {ADDABLE_LAYER_TYPES.map((type) => (
                <button
                  key={type}
                  type="button"
                  className={`add-layer-btn layer-chip-${type}`}
                  onClick={() => handleAddLayer(type)}
                >
                  + {LAYER_META[type].shortName}
                </button>
              ))}
            </div>
          </div>

          <div className="layer-stack">
            {layerItems.length === 0 && (
              <div className="empty-stack-note">
                No header layers yet. Use &quot;+ ETH&quot;, &quot;+ IPv4&quot;, or another button above to stack layers.
              </div>
            )}

            {layerItems.map((item, index) => {
              const layerErrors = draft.errors.filter((e) => e.layerIndex === index);
              const layerWarnings = draft.warnings.filter((w) => w.layerIndex === index);
              const resolvedAuto = draft.resolvedAutoValues?.[index];

              return (
                <LayerCard
                  key={item.id}
                  id={item.id}
                  index={index}
                  total={layerItems.length}
                  layer={item.layer}
                  spans={draft.spans}
                  highlight={highlight}
                  resolvedAutoValues={resolvedAuto}
                  errors={layerErrors}
                  warnings={layerWarnings}
                  onHighlightChange={setHighlight}
                  onChange={(next) => handleLayerChange(index, next)}
                  onMoveUp={() => handleMoveLayer(index, -1)}
                  onMoveDown={() => handleMoveLayer(index, 1)}
                  onRemove={() => handleRemoveLayer(index)}
                />
              );
            })}

            <PayloadCard
              mode={payloadMode}
              textValue={payloadText}
              hexValue={payloadHex}
              byteLength={payloadResult.ok ? payloadResult.value.length : 0}
              error={draft.payloadError}
              modeSwitchError={payloadModeSwitchError}
              isHighlighted={isPayloadHighlighted}
              onHoverStart={() =>
                setHighlight({ kind: 'field', layerIndex: payloadLayerIndex, fieldId: 'payload' })
              }
              onHoverEnd={() => setHighlight(null)}
              onModeChange={handlePayloadModeChange}
              onTextChange={(next) => {
                markUserEdited();
                setActivePresetId(null);
                setPayloadText(next);
              }}
              onHexChange={(next) => {
                markUserEdited();
                setActivePresetId(null);
                setPayloadModeSwitchError(undefined);
                setPayloadHex(next);
              }}
            />
          </div>
        </section>

        <div className="inspector-column">
          <HexDumpInspector
            layers={layers}
            draft={draft}
            highlight={highlight}
            permalinkUrl={permalinkUrl}
            roundTripReport={roundTripReport}
            onHighlightChange={setHighlight}
          />
        </div>
      </main>
    </div>
  );
}
