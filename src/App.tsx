import { useMemo, useRef, useState } from 'react';
import { decodeUtf8Strict, encodeUtf8, parseHexBytes } from './core/bytes';
import { evaluatePacketDraft, formatSpacedHex } from './core/inspector';
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
    setLayerItems((prev) => {
      const copy = [...prev];
      const [moved] = copy.splice(index, 1);
      copy.splice(targetIndex, 0, moved);
      return copy;
    });
  };

  const handleRemoveLayer = (index: number) => {
    setActivePresetId(null);
    setLayerItems((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAddLayer = (type: LayerType) => {
    setActivePresetId(null);
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

    // Hex -> Text への切替時は、現在の Hex を UTF-8 として厳密に復元できた場合のみ切り替える
    const parsed = parseHexBytes(payloadHex);
    if (!parsed.ok) {
      setPayloadModeSwitchError(
        `16 進入力にエラーがあるためテキストモードへ切り替えられません（${parsed.error}）`,
      );
      return;
    }
    const decoded = decodeUtf8Strict(parsed.value);
    if (!decoded.ok) {
      setPayloadModeSwitchError(
        `${decoded.error} テキストモードへ切り替える前に 16 進内容を修正してください。`,
      );
      return;
    }
    setPayloadText(decoded.value);
    setPayloadModeSwitchError(undefined);
    setPayloadMode('text');
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <div className="brand-title-row">
            <h1 className="brand-title">tsumiki</h1>
            <span className="brand-sub">packet builder</span>
          </div>
          <p className="brand-desc">
            Ethernet II / IPv4 / ICMP / UDP / TCP のレイヤーを積み木のように重ねて、パケットのバイト列を組み立てて学べるツールです。
          </p>
        </div>

        <nav className="preset-bar" aria-label="プリセット切り替え">
          <span className="preset-label">プリセット</span>
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
        <section className="stack-column" aria-label="レイヤー積み木エディタ">
          <div className="stack-toolbar">
            <h2 className="section-heading">レイヤー構成（外側から順に）</h2>
            <div className="add-layer-bar" role="group" aria-label="レイヤーを追加">
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
                ヘッダレイヤーがありません。上の「+ ETH」「+ IPv4」などからレイヤーを追加できます。
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
                  resolvedAutoValues={resolvedAuto}
                  errors={layerErrors}
                  warnings={layerWarnings}
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
          <HexDumpInspector draft={draft} />
        </div>
      </main>
    </div>
  );
}
