import { useMemo, useRef, useState } from 'react';
import { decodeUtf8Strict, encodeUtf8, parseHexBytes } from './core/bytes';
import {
  evaluatePacketDraft,
  formatSpacedHex,
  isFieldHighlighted,
  type HighlightTarget,
} from './core/inspector';
import type { Layer, LayerType } from './core/layers/types';
import { createPresets, type PacketPreset, type PresetId } from './core/presets';
import { ok, type Result } from './core/result';
import { HexDumpInspector } from './ui/HexDumpInspector';
import { LayerCard } from './ui/LayerCard';
import { ADDABLE_LAYER_TYPES, createLayerByType, LAYER_META } from './ui/layerMeta';
import { PayloadCard, type PayloadMode } from './ui/PayloadCard';

interface LayerItem {
  readonly id: string;
  readonly layer: Layer;
}

export function App() {
  const presets = useMemo(() => createPresets(), []);
  const nextIdRef = useRef(1);
  const allocateId = () => `layer-${nextIdRef.current++}`;

  const [activePresetId, setActivePresetId] = useState<PresetId | null>(presets[0].id);
  const [layerItems, setLayerItems] = useState<LayerItem[]>(() =>
    presets[0].layers.map((layer) => ({ id: allocateId(), layer })),
  );
  const [payloadMode, setPayloadMode] = useState<PayloadMode>('text');
  const [payloadText, setPayloadText] = useState<string>(presets[0].payloadText);
  const [payloadHex, setPayloadHex] = useState<string>(() =>
    formatSpacedHex(presets[0].payloadBytes),
  );
  const [payloadModeSwitchError, setPayloadModeSwitchError] = useState<string | undefined>(
    undefined,
  );
  const [highlight, setHighlight] = useState<HighlightTarget | null>(null);

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

  const applyPreset = (preset: PacketPreset) => {
    setActivePresetId(preset.id);
    setLayerItems(preset.layers.map((layer) => ({ id: allocateId(), layer })));
    setPayloadMode('text');
    setPayloadText(preset.payloadText);
    setPayloadHex(formatSpacedHex(preset.payloadBytes));
    setPayloadModeSwitchError(undefined);
    setHighlight(null);
  };

  const handleLayerChange = (index: number, nextLayer: Layer) => {
    setActivePresetId(null);
    setLayerItems((prev) =>
      prev.map((item, i) => (i === index ? { ...item, layer: nextLayer } : item)),
    );
  };

  const handleMoveLayer = (index: number, delta: -1 | 1) => {
    const targetIndex = index + delta;
    if (targetIndex < 0 || targetIndex >= layerItems.length) {
      return;
    }
    setActivePresetId(null);
    setHighlight(null);
    setLayerItems((prev) => {
      const copy = [...prev];
      const [moved] = copy.splice(index, 1);
      copy.splice(targetIndex, 0, moved);
      return copy;
    });
  };

  const handleRemoveLayer = (index: number) => {
    setActivePresetId(null);
    setHighlight(null);
    setLayerItems((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAddLayer = (type: LayerType) => {
    setActivePresetId(null);
    setHighlight(null);
    setLayerItems((prev) => [...prev, { id: allocateId(), layer: createLayerByType(type) }]);
  };

  const handlePayloadModeChange = (nextMode: PayloadMode) => {
    if (nextMode === payloadMode) return;

    if (nextMode === 'hex') {
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
            Stack Ethernet II, ARP, IPv4, ICMP, UDP, and TCP layers like building blocks to inspect and export raw network packets.
          </p>
        </div>

        <nav className="preset-bar" aria-label="Packet presets">
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
          </div>
        </nav>
      </header>

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
                setActivePresetId(null);
                setPayloadText(next);
              }}
              onHexChange={(next) => {
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
            onHighlightChange={setHighlight}
          />
        </div>
      </main>
    </div>
  );
}
