import type { Result } from '../result';
import type {
  FieldDoc,
  LayerEncodeResult,
  PacketError,
  PacketWarning,
  RelativeFieldSpan,
} from './types';

export type { FieldDoc };

/** Minimum shape shared by every registered layer (including test-only custom layers). */
export interface BaseLayer {
  readonly type: string;
}

/**
 * Underlying IPv4 or IPv6 header state needed for UDP / TCP / ICMPv6 pseudo-header checksums.
 */
export type IPPseudoContext =
  | { readonly status: 'absent' }
  | { readonly status: 'invalid'; readonly version: 4 | 6 }
  | {
      readonly status: 'valid';
      readonly version: 4 | 6;
      readonly srcIp: Uint8Array;
      readonly dstIp: Uint8Array;
    };

/** Underlying UDP header state for protocols carried over UDP (e.g., VXLAN). */
export type UDPTransportContext =
  | { readonly status: 'absent' }
  | { readonly status: 'invalid' }
  | { readonly status: 'valid'; readonly srcPort: number; readonly dstPort: number };

/** Underlying TCP header state for protocols carried over TCP (e.g., BGP-4). */
export type TCPTransportContext =
  | { readonly status: 'absent' }
  | { readonly status: 'invalid' }
  | { readonly status: 'valid'; readonly srcPort: number; readonly dstPort: number };

/** Context exported by a lower layer to the layer sitting immediately above it during build. */
export interface LowerLayerContext {
  readonly ip?: IPPseudoContext;
  readonly udp?: UDPTransportContext;
  readonly tcp?: TCPTransportContext;
}

/**
 * Protocol numbers and carrier identifiers declared by a layer module.
 * Each identifier is defined once here and compiled into bidirectional lookup tables
 * (carrier inference during encoding + protocol dispatch during decoding).
 */
export interface NextProtocolSpec {
  /** Standard EtherType when carried by Ethernet II / VLAN (e.g., 0x0800 IPv4, 0x8100 VLAN). */
  readonly etherType?: number;
  /** EtherType used when two instances of this layer are stacked directly (e.g., 0x88a8 QinQ S-tag). */
  readonly stackedEtherType?: number;
  /** Additional legacy/alternate EtherTypes recognized only when decoding (e.g., 0x9100). */
  readonly decodeEtherTypes?: readonly number[];
  /** Display label for EtherType mismatch warnings (e.g., 'IPv4', 'ARP', '802.1Q VLAN'). */
  readonly etherTypeLabel?: string;
  /** Display label when stacked (e.g., '802.1ad QinQ S-tag'). */
  readonly stackedEtherTypeLabel?: string;
  /** Display label when sitting directly inside a VLAN tag, if different from etherTypeLabel. */
  readonly vlanInnerEtherTypeLabel?: string;

  /** Standard IPv4 Protocol number and IPv6 Next Header when identical (e.g., 4, 6, 17, 41, 47). */
  readonly ipProtocol?: number;
  /** Standard IPv4-only Protocol number (e.g., ICMPv4 = 1). */
  readonly ipv4Protocol?: number;
  /** Standard IPv6-only Next Header number (e.g., ICMPv6 = 58). */
  readonly ipv6NextHeader?: number;
  /** Warning emitted by IPv6 if this layer sits directly above IPv6 (e.g., ICMPv4 above IPv6). */
  readonly ipv6MismatchWarning?: string;

  /** Standard GRE Protocol Type when different from etherType (e.g., 0x6558 Ethernet TEB). */
  readonly greProtocolType?: number;
  /** Display label for GRE mismatch warnings. */
  readonly greLabel?: string;

  /** Well-known UDP destination port (e.g., 4789 for VXLAN). */
  readonly udpPort?: number;
  /** True when a 0x0000 outer UDP checksum over IPv4 is standard and should not emit a warning. */
  readonly allowsZeroUdpChecksumOverIPv4?: boolean;

  /** Well-known TCP port matched on srcPort or dstPort (e.g., 179 for BGP-4). */
  readonly tcpPort?: number;

  /** Marks this layer as the inner L2 frame carried by L2-over-UDP tunnels such as VXLAN. */
  readonly isLinkFrame?: boolean;
}

export interface ResolvedProtocolInfo {
  readonly value: number;
  readonly label: string;
}

/** Shared bidirectional next-protocol lookup tables derived from a LayerRegistry. */
export interface ProtocolTables<L extends BaseLayer = BaseLayer> {
  /** Default fallback EtherType (IPv4 0x0800) when upper layer has no registered EtherType. */
  readonly defaultEtherType: number;
  /** Resolves the Ethernet II EtherType/TPID for (upperLayerType, upperNextLayerType). */
  resolveEthernetEtherType(
    upperLayerType: string | null,
    upperNextLayerType?: string | null,
  ): ResolvedProtocolInfo | null;
  /** Resolves the VLAN inner EtherType/TPID for upperLayerType. */
  resolveVlanEtherType(upperLayerType: string | null): ResolvedProtocolInfo | null;
  /** Resolves the GRE Protocol Type for upperLayerType. */
  resolveGreProtocolType(upperLayerType: string | null): ResolvedProtocolInfo | null;
  /** Resolves the IPv4 Protocol number for upperLayerType. */
  resolveIPv4Protocol(upperLayerType: string | null): number | null;
  /** Resolves the IPv6 Next Header number for upperLayerType. */
  resolveIPv6NextHeader(upperLayerType: string | null): number | null;
  /** Returns an incompatibility warning when upperLayerType sits directly above IPv6, if any. */
  getIPv6MismatchWarning(upperLayerType: string | null): string | null;
  /** Returns true if upperLayerType permits 0x0000 UDP checksum over IPv4 without warning. */
  allowsZeroUdpChecksumOverIPv4(upperLayerType: string | null): boolean;

  /** Decode dispatch maps (number -> owning LayerDefinition). */
  readonly byEtherType: ReadonlyMap<number, LayerDefinition<L>>;
  readonly byGreProtocolType: ReadonlyMap<number, LayerDefinition<L>>;
  readonly byIPv4Protocol: ReadonlyMap<number, LayerDefinition<L>>;
  readonly byIPv6NextHeader: ReadonlyMap<number, LayerDefinition<L>>;
  readonly byUdpPort: ReadonlyMap<number, LayerDefinition<L>>;
  readonly byTcpPort: ReadonlyMap<number, LayerDefinition<L>>;
  /** Layer definition marked with `isLinkFrame: true` (Ethernet II). */
  readonly linkFrameLayer: LayerDefinition<L> | undefined;
}

/** Unified encode context passed by `buildPacket` to every layer's `encode`. */
export interface LayerEncodeContext {
  readonly layerIndex: number;
  readonly upperLayerType: string | null;
  readonly upperNextLayerType: string | null;
  readonly upperBytes: Uint8Array;
  readonly upperBytesLength: number;
  readonly ip: IPPseudoContext;
  readonly udp: UDPTransportContext;
  readonly tcp: TCPTransportContext;
  readonly tables: ProtocolTables;
}

/** Pseudo-header IP info carried downward during packet decoding. */
export interface PseudoIPInfo {
  readonly version: 4 | 6;
  readonly srcIp: Uint8Array;
  readonly dstIp: Uint8Array;
}

export type DecodeCarrierKind =
  | 'start'
  | 'etherType'
  | 'greProtocol'
  | 'ipv4Protocol'
  | 'ipv6NextHeader'
  | 'udpPort'
  | 'tcpPort'
  | 'linkFrame';

export interface DecodeChainResult<L extends BaseLayer = BaseLayer> {
  readonly layers: readonly L[];
  readonly payload: Uint8Array;
}

/** Context passed to each layer's `decode` hook during packet decoding. */
export interface DecodeLayerContext<L extends BaseLayer = BaseLayer> {
  readonly carrier: DecodeCarrierKind;
  /** Human-readable enclosing carrier label (e.g. 'Ethernet II', 'VLAN tag', 'GRE', 'Protocol 4'). */
  readonly enclosingLabel: string;
  /** Raw EtherType/TPID/protocol/port number that dispatched to this layer, when applicable. */
  readonly dispatchedValue?: number;
  /** Origin parent kind for EtherType chains ('link' for L2 frames or 'tunnel' for GRE). */
  readonly etherTypeParentKind: 'link' | 'tunnel';
  /** Current VLAN tag nesting depth. */
  readonly vlanDepth: number;
  /** Current IP/tunnel nesting depth. */
  readonly tunnelDepth: number;
  /** Enclosing IP pseudo-header info for L4 checksum verification. */
  readonly ip?: PseudoIPInfo;
  /** TCP framing metadata for upper-layer decoders like BGP. */
  readonly tcpDataOffsetAuto?: boolean;
  readonly tcpDataOffsetValue?: number;
  readonly notes: string[];
  readonly tables: ProtocolTables<L>;

  /** Dispatch helpers that use the registry's next-protocol tables. */
  decodeByEtherType(
    bytes: Uint8Array,
    offset: number,
    etherType: number,
    opts?: {
      readonly vlanDepth?: number;
      readonly tunnelDepth?: number;
      readonly parentKind?: 'link' | 'tunnel';
    },
  ): DecodeChainResult<L>;
  decodeByGreProtocol(
    bytes: Uint8Array,
    offset: number,
    protocolType: number,
    tunnelDepth: number,
  ): DecodeChainResult<L>;
  decodeByIPv4Protocol(
    bytes: Uint8Array,
    offset: number,
    protocol: number,
    ip: PseudoIPInfo,
    tunnelDepth: number,
  ): DecodeChainResult<L>;
  decodeByIPv6NextHeader(
    bytes: Uint8Array,
    offset: number,
    nextHeader: number,
    ip: PseudoIPInfo,
    tunnelDepth: number,
  ): DecodeChainResult<L>;
  decodeByUdpPort(
    bytes: Uint8Array,
    offset: number,
    dstPort: number,
    tunnelDepth: number,
  ): DecodeChainResult<L>;
  decodeByTcpPort(
    bytes: Uint8Array,
    offset: number,
    srcPort: number,
    dstPort: number,
    opts: { readonly dataOffsetAuto: boolean; readonly dataOffsetValue: number },
  ): DecodeChainResult<L>;
  decodeLinkFrame(
    bytes: Uint8Array,
    offset: number,
    tunnelDepth: number,
    enclosingLabel: string,
  ): DecodeChainResult<L>;
}

/** Result returned by a layer's `decode` hook (`null` = not decoded; keep bytes as payload). */
export type LayerDecodeResult<L extends BaseLayer = BaseLayer> = {
  readonly layers: readonly L[];
  readonly payload: Uint8Array;
} | null;

/**
 * Self-contained core protocol definition registered in `src/core/layers/registry.ts`.
 */
export interface LayerDefinition<
  L extends BaseLayer = BaseLayer,
  TType extends L['type'] = L['type'],
> {
  readonly type: TType;
  /** Minimum header length in bytes (used for truncation checks during decoding). */
  readonly minHeaderLength: number;
  /** Creates a valid default instance of this layer. */
  createDefault(): L;
  /** Computes the encoded header byte length for this layer (used when inner layers have errors). */
  headerLength(layer: L): number;
  /** Encodes this layer into raw bytes, relative field spans, warnings, and auto-resolved values. */
  encode(layer: L, ctx: LayerEncodeContext): LayerEncodeResult;
  /** Optionally provides lower-layer context (IP pseudo-header, UDP/TCP ports) to the layer above. */
  provideLowerContext?(layer: L): LowerLayerContext;
  /** Validates and decodes this layer when selected as the outermost start layer of `decodePacket`. */
  decodeStart?(
    bytes: Uint8Array,
    ctx: DecodeLayerContext<BaseLayer>,
  ): Result<{ readonly layers: readonly BaseLayer[]; readonly payload: Uint8Array }>;
  /** Decodes this layer when dispatched from an enclosing carrier layer. */
  decode(
    bytes: Uint8Array,
    offset: number,
    ctx: DecodeLayerContext<BaseLayer>,
  ): LayerDecodeResult<BaseLayer>;
  /** Strictly validates a decoded permalink JSON object for this layer. */
  validatePermalink(raw: Record<string, unknown>, context: string): Result<L>;
  /** Exhaustive RFC / IEEE per-field documentation keyed by FieldSpan.fieldId. */
  readonly fieldDocs: Readonly<Record<string, FieldDoc>>;
  /** Protocol identifiers for bidirectional carrier/next-protocol lookup tables. */
  readonly protocols?: NextProtocolSpec;
}

export interface LayerRegistry<L extends BaseLayer = BaseLayer> {
  readonly definitions: readonly LayerDefinition<L>[];
  readonly types: readonly L['type'][];
  readonly byType: ReadonlyMap<string, LayerDefinition<L>>;
  readonly tables: ProtocolTables<L>;
  readonly fieldDocs: Readonly<Record<string, Readonly<Record<string, FieldDoc>>>>;
  get(type: string): LayerDefinition<L> | undefined;
}

/** Maximum total IP/tunnel layers decoded to guard against pathological inputs. */
export const MAX_IP_LAYERS = 16;
/** Maximum stacked VLAN tags decoded to guard against pathological inputs. */
export const MAX_VLAN_TAGS = 16;

/**
 * Compiles bidirectional next-protocol lookup tables from an ordered list of layer definitions.
 */
export function buildProtocolTables<L extends BaseLayer>(
  definitions: readonly LayerDefinition<L>[],
): ProtocolTables<L> {
  const byType = new Map<string, LayerDefinition<L>>();
  const byEtherType = new Map<number, LayerDefinition<L>>();
  const byGreProtocolType = new Map<number, LayerDefinition<L>>();
  const byIPv4Protocol = new Map<number, LayerDefinition<L>>();
  const byIPv6NextHeader = new Map<number, LayerDefinition<L>>();
  const byUdpPort = new Map<number, LayerDefinition<L>>();
  const byTcpPort = new Map<number, LayerDefinition<L>>();
  let linkFrameLayer: LayerDefinition<L> | undefined;
  let defaultEtherType = 0x0800;

  for (const def of definitions) {
    byType.set(def.type, def);
    const p = def.protocols;
    if (!p) continue;

    if (p.etherType !== undefined) {
      byEtherType.set(p.etherType, def);
      if (p.greProtocolType === undefined) {
        byGreProtocolType.set(p.etherType, def);
      }
    }
    if (p.stackedEtherType !== undefined) {
      byEtherType.set(p.stackedEtherType, def);
    }
    if (p.decodeEtherTypes) {
      for (const et of p.decodeEtherTypes) {
        byEtherType.set(et, def);
      }
    }
    if (p.greProtocolType !== undefined) {
      byGreProtocolType.set(p.greProtocolType, def);
    }

    const v4Proto = p.ipv4Protocol ?? p.ipProtocol;
    if (v4Proto !== undefined) {
      byIPv4Protocol.set(v4Proto, def);
    }
    const v6Proto = p.ipv6NextHeader ?? p.ipProtocol;
    if (v6Proto !== undefined) {
      byIPv6NextHeader.set(v6Proto, def);
    }

    if (p.udpPort !== undefined) {
      byUdpPort.set(p.udpPort, def);
    }
    if (p.tcpPort !== undefined) {
      byTcpPort.set(p.tcpPort, def);
    }
    if (p.isLinkFrame) {
      linkFrameLayer = def;
    }
  }

  // Prefer the first registered IPv4-like EtherType (0x0800) if present
  for (const def of definitions) {
    if (def.protocols?.etherType === 0x0800) {
      defaultEtherType = def.protocols.etherType;
      break;
    }
  }

  return {
    defaultEtherType,
    resolveEthernetEtherType(upperLayerType, upperNextLayerType = null) {
      if (!upperLayerType) return null;
      const def = byType.get(upperLayerType);
      const p = def?.protocols;
      if (!p || p.etherType === undefined) return null;
      if (upperNextLayerType === upperLayerType && p.stackedEtherType !== undefined) {
        return {
          value: p.stackedEtherType,
          label: p.stackedEtherTypeLabel ?? p.etherTypeLabel ?? upperLayerType,
        };
      }
      return {
        value: p.etherType,
        label: p.etherTypeLabel ?? upperLayerType,
      };
    },
    resolveVlanEtherType(upperLayerType) {
      if (!upperLayerType) return null;
      const def = byType.get(upperLayerType);
      const p = def?.protocols;
      if (!p || p.etherType === undefined) return null;
      return {
        value: p.etherType,
        label: p.vlanInnerEtherTypeLabel ?? p.etherTypeLabel ?? upperLayerType,
      };
    },
    resolveGreProtocolType(upperLayerType) {
      if (!upperLayerType) return null;
      const def = byType.get(upperLayerType);
      const p = def?.protocols;
      if (!p) return null;
      const value = p.greProtocolType ?? p.etherType;
      if (value === undefined) return null;
      return {
        value,
        label: p.greLabel ?? p.etherTypeLabel ?? upperLayerType,
      };
    },
    resolveIPv4Protocol(upperLayerType) {
      if (!upperLayerType) return null;
      const p = byType.get(upperLayerType)?.protocols;
      return p ? (p.ipv4Protocol ?? p.ipProtocol ?? null) : null;
    },
    resolveIPv6NextHeader(upperLayerType) {
      if (!upperLayerType) return null;
      const p = byType.get(upperLayerType)?.protocols;
      return p ? (p.ipv6NextHeader ?? p.ipProtocol ?? null) : null;
    },
    getIPv6MismatchWarning(upperLayerType) {
      if (!upperLayerType) return null;
      return byType.get(upperLayerType)?.protocols?.ipv6MismatchWarning ?? null;
    },
    allowsZeroUdpChecksumOverIPv4(upperLayerType) {
      if (!upperLayerType) return false;
      return Boolean(byType.get(upperLayerType)?.protocols?.allowsZeroUdpChecksumOverIPv4);
    },
    byEtherType,
    byGreProtocolType,
    byIPv4Protocol,
    byIPv6NextHeader,
    byUdpPort,
    byTcpPort,
    linkFrameLayer,
  };
}

/**
 * Creates a LayerRegistry from an ordered list of protocol definitions.
 * Can be called in tests with custom or dummy layer definitions without editing production code.
 */
export function createLayerRegistry<L extends BaseLayer>(
  definitions: readonly LayerDefinition<L>[],
): LayerRegistry<L> {
  const byType = new Map<string, LayerDefinition<L>>();
  const fieldDocs: Record<string, Readonly<Record<string, FieldDoc>>> = {};
  const types: L['type'][] = [];

  for (const def of definitions) {
    byType.set(def.type, def);
    fieldDocs[def.type] = def.fieldDocs;
    types.push(def.type);
  }

  return {
    definitions,
    types,
    byType,
    tables: buildProtocolTables(definitions),
    fieldDocs,
    get(type: string) {
      return byType.get(type);
    },
  };
}

// Re-export common encode types for convenience inside layer modules
export type { LayerEncodeResult, PacketError, PacketWarning, RelativeFieldSpan };
