import { concatBytes } from './bytes';
import type { BaseLayer, LayerRegistry, ProtocolTables } from './layers/definition';
import { getDefaultLayerRegistry } from './layers/registry';
import type {
  BuildPacketResult,
  FieldSpan,
  Layer,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './layers/types';

/**
 * Builds raw packet bytes and contiguous per-field bit spans from an arbitrary stack
 * of protocol layers (outer to inner) and a payload.
 */
export function buildPacket(layers: readonly Layer[], payload: Uint8Array): BuildPacketResult;
export function buildPacket<L extends BaseLayer>(
  layers: readonly L[],
  payload: Uint8Array,
  registry: LayerRegistry<L>,
): BuildPacketResult;
export function buildPacket<L extends BaseLayer>(
  layers: readonly L[],
  payload: Uint8Array,
  registry: LayerRegistry<L> = getDefaultLayerRegistry() as unknown as LayerRegistry<L>,
): BuildPacketResult {
  const count = layers.length;
  const encodedHeaders: (Uint8Array | null)[] = new Array(count).fill(null);
  const relativeSpans: (readonly RelativeFieldSpan[] | null)[] = new Array(count).fill(null);
  const resolvedAutoValues: Readonly<Record<string, number>>[] = new Array(count).fill({});
  const layerErrors: PacketError[][] = Array.from({ length: count }, () => []);
  const layerWarnings: PacketWarning[][] = Array.from({ length: count }, () => []);
  const tables = registry.tables as unknown as ProtocolTables<BaseLayer>;

  // 内側（上位層）から外側（下位層）へ向かって長さとチェックサムを解決しながらエンコードする
  let currentUpperBytes: Uint8Array = payload;

  for (let i = count - 1; i >= 0; i--) {
    const layer = layers[i];
    const def = registry.get(layer.type);
    if (!def) {
      layerErrors[i].push({
        layerIndex: i,
        message: `Unknown layer type "${layer.type}".`,
      });
      continue;
    }

    const upperLayerType: string | null = i + 1 < count ? layers[i + 1].type : null;
    const upperNextLayerType: string | null = i + 2 < count ? layers[i + 2].type : null;

    // Resolve lower-layer context strictly from the immediately preceding layer (layers[i - 1])
    // so inner layers never mistakenly inherit outer tunnel headers across intermediate layers.
    const prevLayer = i > 0 ? layers[i - 1] : undefined;
    const prevDef = prevLayer ? registry.get(prevLayer.type) : undefined;
    const lower = prevLayer && prevDef?.provideLowerContext
      ? prevDef.provideLowerContext(prevLayer)
      : {};

    const result = def.encode(layer, {
      layerIndex: i,
      upperLayerType,
      upperNextLayerType,
      upperBytes: currentUpperBytes,
      upperBytesLength: currentUpperBytes.length,
      ip: lower.ip ?? { status: 'absent' },
      udp: lower.udp ?? { status: 'absent' },
      tcp: lower.tcp ?? { status: 'absent' },
      tables,
    });

    layerWarnings[i].push(...result.warnings);
    if (result.ok) {
      encodedHeaders[i] = result.bytes;
      relativeSpans[i] = result.spans;
      resolvedAutoValues[i] = result.resolvedAutoValues;
      currentUpperBytes = concatBytes(result.bytes, currentUpperBytes);
    } else {
      layerErrors[i].push(...result.errors);
      // 外側レイヤーの検証も継続できるよう、ヘッダ長分のプレースホルダを積む
      currentUpperBytes = concatBytes(
        new Uint8Array(def.headerLength(layer)),
        currentUpperBytes,
      );
    }
  }

  // エラー・警告はレイヤー配列の並び順（外側 -> 内側）に整える
  const errors = layerErrors.flat();
  const warnings = layerWarnings.flat();

  if (errors.length > 0) {
    return { ok: false, errors, warnings };
  }

  const allParts: Uint8Array[] = [];
  const spans: FieldSpan[] = [];
  let bitCursor = 0;

  for (let i = 0; i < count; i++) {
    const headerBytes = encodedHeaders[i]!;
    const relSpans = relativeSpans[i]!;
    allParts.push(headerBytes);

    for (const span of relSpans) {
      spans.push({
        section: 'layer',
        layerIndex: i,
        layerType: layers[i].type as LayerType,
        fieldId: span.fieldId,
        label: span.label,
        bitOffset: bitCursor + span.bitOffset,
        bitLength: span.bitLength,
      });
    }
    bitCursor += headerBytes.length * 8;
  }

  allParts.push(payload);
  if (payload.length > 0) {
    spans.push({
      section: 'payload',
      layerIndex: count,
      layerType: 'payload',
      fieldId: 'payload',
      label: 'Payload',
      bitOffset: bitCursor,
      bitLength: payload.length * 8,
    });
  }

  return {
    ok: true,
    bytes: concatBytes(...allParts),
    spans,
    warnings,
    resolvedAutoValues,
  };
}
