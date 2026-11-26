import { concatBytes, parseIPv4, parseIPv6 } from './bytes';
import { ARP_HEADER_LENGTH, encodeARP } from './layers/arp';
import {
  encodeBGP,
  getBGPHeaderLength,
  type BGPUnderlyingTCPContext,
} from './layers/bgp';
import { ETHERNET_HEADER_LENGTH, encodeEthernet } from './layers/ethernet';
import { encodeGRE, getGREHeaderLength } from './layers/gre';
import { ICMP_HEADER_LENGTH, encodeICMP } from './layers/icmp';
import { ICMPV6_HEADER_LENGTH, encodeICMPv6 } from './layers/icmpv6';
import { encodeIPv4, getIPv4HeaderLength } from './layers/ipv4';
import { IPV6_HEADER_LENGTH, encodeIPv6 } from './layers/ipv6';
import { encodeTCP, getTCPHeaderLength } from './layers/tcp';
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
import { UDP_HEADER_LENGTH, encodeUDP, type IPPseudoContext } from './layers/udp';
import { VLAN_HEADER_LENGTH, encodeVLAN } from './layers/vlan';
import {
  VXLAN_HEADER_LENGTH,
  encodeVXLAN,
  type VXLANUnderlyingUDPContext,
} from './layers/vxlan';

function getLayerHeaderLength(layer: Layer): number {
  switch (layer.type) {
    case 'ethernet':
      return ETHERNET_HEADER_LENGTH;
    case 'vlan':
      return VLAN_HEADER_LENGTH;
    case 'arp':
      return ARP_HEADER_LENGTH;
    case 'ipv4':
      return getIPv4HeaderLength(layer);
    case 'ipv6':
      return IPV6_HEADER_LENGTH;
    case 'icmp':
      return ICMP_HEADER_LENGTH;
    case 'icmpv6':
      return ICMPV6_HEADER_LENGTH;
    case 'gre':
      return getGREHeaderLength(layer);
    case 'udp':
      return UDP_HEADER_LENGTH;
    case 'tcp':
      return getTCPHeaderLength(layer);
    case 'vxlan':
      return VXLAN_HEADER_LENGTH;
    case 'bgp':
      return getBGPHeaderLength(layer.bgpType);
  }
}

/**
 * Resolves the immediately preceding IPv4 or IPv6 layer for UDP/TCP/ICMPv6 pseudo-header checksum calculation.
 * Checking only `layers[layerIndex - 1]` avoids mistakenly inheriting an outer tunnel's IP
 * addresses across intermediate headers (e.g., Outer IPv4 -> IPv6 -> UDP uses inner IPv6).
 */
function resolveIPContextBefore(layers: readonly Layer[], layerIndex: number): IPPseudoContext {
  const prev = layerIndex > 0 ? layers[layerIndex - 1] : undefined;
  if (!prev) {
    return { status: 'absent' };
  }
  if (prev.type === 'ipv4') {
    const src = parseIPv4(prev.srcIp);
    const dst = parseIPv4(prev.dstIp);
    if (src.ok && dst.ok) {
      return { status: 'valid', version: 4, srcIp: src.value, dstIp: dst.value };
    }
    return { status: 'invalid', version: 4 };
  }
  if (prev.type === 'ipv6') {
    const src = parseIPv6(prev.srcIp);
    const dst = parseIPv6(prev.dstIp);
    if (src.ok && dst.ok) {
      return { status: 'valid', version: 6, srcIp: src.value, dstIp: dst.value };
    }
    return { status: 'invalid', version: 6 };
  }
  return { status: 'absent' };
}

/**
 * Resolves the immediately preceding TCP layer state for BGP RFC 4271 transport / port-179 hints.
 */
function resolveTCPContextBefore(
  layers: readonly Layer[],
  layerIndex: number,
): BGPUnderlyingTCPContext {
  const prev = layerIndex > 0 ? layers[layerIndex - 1] : undefined;
  if (!prev || prev.type !== 'tcp') {
    return { status: 'absent' };
  }
  if (
    Number.isInteger(prev.srcPort) &&
    prev.srcPort >= 0 &&
    prev.srcPort <= 0xffff &&
    Number.isInteger(prev.dstPort) &&
    prev.dstPort >= 0 &&
    prev.dstPort <= 0xffff
  ) {
    return { status: 'valid', srcPort: prev.srcPort, dstPort: prev.dstPort };
  }
  return { status: 'invalid' };
}

/**
 * Resolves the immediately preceding UDP layer state for VXLAN RFC 7348 §5 transport / port-4789 hints.
 * Checking only `layers[layerIndex - 1]` avoids inheriting an outer tunnel's UDP header across intermediate layers.
 */
function resolveUDPContextBefore(
  layers: readonly Layer[],
  layerIndex: number,
): VXLANUnderlyingUDPContext {
  const prev = layerIndex > 0 ? layers[layerIndex - 1] : undefined;
  if (!prev || prev.type !== 'udp') {
    return { status: 'absent' };
  }
  if (
    Number.isInteger(prev.srcPort) &&
    prev.srcPort >= 0 &&
    prev.srcPort <= 0xffff &&
    Number.isInteger(prev.dstPort) &&
    prev.dstPort >= 0 &&
    prev.dstPort <= 0xffff
  ) {
    return { status: 'valid', srcPort: prev.srcPort, dstPort: prev.dstPort };
  }
  return { status: 'invalid' };
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
    const upperNextLayerType: LayerType | null = i + 2 < count ? layers[i + 2].type : null;
    let result: LayerEncodeResult;

    switch (layer.type) {
      case 'ethernet':
        result = encodeEthernet(layer, {
          layerIndex: i,
          upperLayerType,
          upperNextLayerType,
          upperBytesLength: currentUpperBytes.length,
        });
        break;
      case 'vlan':
        result = encodeVLAN(layer, {
          layerIndex: i,
          upperLayerType,
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
      case 'ipv6':
        result = encodeIPv6(layer, {
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
      case 'icmpv6':
        result = encodeICMPv6(layer, {
          layerIndex: i,
          upperBytes: currentUpperBytes,
          ip: resolveIPContextBefore(layers, i),
        });
        break;
      case 'gre':
        result = encodeGRE(layer, {
          layerIndex: i,
          upperLayerType,
          upperBytes: currentUpperBytes,
        });
        break;
      case 'udp':
        result = encodeUDP(layer, {
          layerIndex: i,
          upperLayerType,
          upperBytes: currentUpperBytes,
          ip: resolveIPContextBefore(layers, i),
        });
        break;
      case 'tcp':
        result = encodeTCP(layer, {
          layerIndex: i,
          upperBytes: currentUpperBytes,
          ip: resolveIPContextBefore(layers, i),
        });
        break;
      case 'vxlan':
        result = encodeVXLAN(layer, {
          layerIndex: i,
          udp: resolveUDPContextBefore(layers, i),
        });
        break;
      case 'bgp':
        result = encodeBGP(layer, {
          layerIndex: i,
          upperBytesLength: currentUpperBytes.length,
          tcp: resolveTCPContextBefore(layers, i),
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
