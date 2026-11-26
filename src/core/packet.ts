import { concatBytes, parseIPv4 } from './bytes';
import { ARP_HEADER_LENGTH, encodeARP } from './layers/arp';
import { encodeBGP, getBGPHeaderLength } from './layers/bgp';
import { ETHERNET_HEADER_LENGTH, encodeEthernet } from './layers/ethernet';
import { ICMP_HEADER_LENGTH, encodeICMP } from './layers/icmp';
import { IPV4_HEADER_LENGTH, encodeIPv4 } from './layers/ipv4';
import { TCP_HEADER_LENGTH, encodeTCP } from './layers/tcp';
import type {
  BuildPacketResult,
  FieldSpan,
  Layer,
  LayerEncodeResult,
  LayerType,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './layers/types';
import { UDP_HEADER_LENGTH, encodeUDP, type IPv4PseudoContext } from './layers/udp';

function getLayerHeaderLength(layer: Layer): number {
  switch (layer.type) {
    case 'ethernet':
      return ETHERNET_HEADER_LENGTH;
    case 'arp':
      return ARP_HEADER_LENGTH;
    case 'ipv4':
      return IPV4_HEADER_LENGTH;
    case 'icmp':
      return ICMP_HEADER_LENGTH;
    case 'udp':
      return UDP_HEADER_LENGTH;
    case 'tcp':
      return TCP_HEADER_LENGTH;
    case 'bgp':
      return getBGPHeaderLength(layer.bgpType);
  }
}

/**
 * Resolves the immediately preceding IPv4 layer for UDP/TCP pseudo-header checksum calculation.
 * Checking only `layers[layerIndex - 1]` avoids mistakenly inheriting an outer tunnel's IPv4
 * addresses across intermediate headers (e.g., Outer IPv4 -> UDP -> Inner Ethernet -> UDP).
 */
function resolveIPv4ContextBefore(layers: readonly Layer[], layerIndex: number): IPv4PseudoContext {
  const prev = layerIndex > 0 ? layers[layerIndex - 1] : undefined;
  if (!prev || prev.type !== 'ipv4') {
    return { status: 'absent' };
  }
  const src = parseIPv4(prev.srcIp);
  const dst = parseIPv4(prev.dstIp);
  if (src.ok && dst.ok) {
    return { status: 'valid', srcIp: src.value, dstIp: dst.value };
  }
  return { status: 'invalid' };
}

/**
 * Resolves the immediately preceding TCP layer's ports for BGP port-179 convention hints.
 */
function resolveTCPPortsBefore(
  layers: readonly Layer[],
  layerIndex: number,
): { readonly srcPort: number; readonly dstPort: number } | null {
  const prev = layerIndex > 0 ? layers[layerIndex - 1] : undefined;
  if (!prev || prev.type !== 'tcp') {
    return null;
  }
  if (
    Number.isInteger(prev.srcPort) &&
    prev.srcPort >= 0 &&
    prev.srcPort <= 0xffff &&
    Number.isInteger(prev.dstPort) &&
    prev.dstPort >= 0 &&
    prev.dstPort <= 0xffff
  ) {
    return { srcPort: prev.srcPort, dstPort: prev.dstPort };
  }
  return null;
}

/**
 * Builds raw packet bytes and contiguous per-field bit spans from an arbitrary stack
 * of protocol layers (outer to inner) and a payload.
 */
export function buildPacket(layers: readonly Layer[], payload: Uint8Array): BuildPacketResult {
  const count = layers.length;
  const encodedHeaders: (Uint8Array | null)[] = new Array(count).fill(null);
  const relativeSpans: (readonly RelativeFieldSpan[] | null)[] = new Array(count).fill(null);
  const resolvedAutoValues: Readonly<Record<string, number>>[] = new Array(count).fill({});
  const layerErrors: PacketError[][] = Array.from({ length: count }, () => []);
  const layerWarnings: PacketWarning[][] = Array.from({ length: count }, () => []);

  // 内側（上位層）から外側（下位層）へ向かって長さとチェックサムを解決しながらエンコードする
  let currentUpperBytes: Uint8Array = payload;

  for (let i = count - 1; i >= 0; i--) {
    const layer = layers[i];
    const upperLayerType: LayerType | null = i + 1 < count ? layers[i + 1].type : null;
    let result: LayerEncodeResult;

    switch (layer.type) {
      case 'ethernet':
        result = encodeEthernet(layer, {
          layerIndex: i,
          upperLayerType,
          upperBytesLength: currentUpperBytes.length,
        });
        break;
      case 'arp':
        result = encodeARP(layer, { layerIndex: i });
        break;
      case 'ipv4':
        result = encodeIPv4(layer, {
          layerIndex: i,
          upperLayerType,
          upperBytesLength: currentUpperBytes.length,
        });
        break;
      case 'icmp':
        result = encodeICMP(layer, {
          layerIndex: i,
          upperBytes: currentUpperBytes,
        });
        break;
      case 'udp':
        result = encodeUDP(layer, {
          layerIndex: i,
          upperBytes: currentUpperBytes,
          ipv4: resolveIPv4ContextBefore(layers, i),
        });
        break;
      case 'tcp':
        result = encodeTCP(layer, {
          layerIndex: i,
          upperBytes: currentUpperBytes,
          ipv4: resolveIPv4ContextBefore(layers, i),
        });
        break;
      case 'bgp':
        result = encodeBGP(layer, {
          layerIndex: i,
          upperBytesLength: currentUpperBytes.length,
          tcpPorts: resolveTCPPortsBefore(layers, i),
        });
        break;
    }

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
        new Uint8Array(getLayerHeaderLength(layer)),
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
        layerType: layers[i].type,
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
