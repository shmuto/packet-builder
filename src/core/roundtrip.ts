import { decodePacket } from './decode';
import type { Layer, LayerType } from './layers/types';
import { buildPacket } from './packet';

export type RoundTripReport =
  | { readonly kind: 'not-built' }
  | { readonly kind: 'reproducible' }
  | {
      readonly kind: 'unsupported-start';
      readonly outerLayerType: LayerType | null;
    }
  | {
      readonly kind: 'differs';
      readonly decodedLayerTypes: readonly LayerType[];
      readonly decodedPayloadLength: number;
    };

function sameLayerTypeSequence(
  expected: readonly Layer[],
  actual: readonly Layer[],
): boolean {
  if (expected.length !== actual.length) {
    return false;
  }
  for (let i = 0; i < expected.length; i++) {
    if (expected[i].type !== actual[i].type) {
      return false;
    }
  }
  return true;
}

/**
 * Checks whether bytes exported from `buildPacket(layers, payload)` will decode back
 * into the same layer type sequence and payload length via `decodePacket`.
 */
export function analyzeDecodeRoundTrip(
  layers: readonly Layer[],
  payload: Uint8Array,
): RoundTripReport {
  const built = buildPacket(layers, payload);
  if (!built.ok) {
    return { kind: 'not-built' };
  }

  if (layers.length === 0) {
    if (payload.length === 0) {
      return { kind: 'not-built' };
    }
    return { kind: 'unsupported-start', outerLayerType: null };
  }

  const outerLayerType = layers[0].type;
  if (outerLayerType !== 'ethernet' && outerLayerType !== 'ipv4') {
    return { kind: 'unsupported-start', outerLayerType };
  }

  const decoded = decodePacket(built.bytes, outerLayerType);
  if (!decoded.ok) {
    return {
      kind: 'differs',
      decodedLayerTypes: [],
      decodedPayloadLength: built.bytes.length,
    };
  }

  if (
    sameLayerTypeSequence(layers, decoded.value.layers) &&
    decoded.value.payload.length === payload.length
  ) {
    return { kind: 'reproducible' };
  }

  return {
    kind: 'differs',
    decodedLayerTypes: decoded.value.layers.map((layer) => layer.type),
    decodedPayloadLength: decoded.value.payload.length,
  };
}
