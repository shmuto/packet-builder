import { ipv4PseudoHeaderChecksum, ipv6PseudoHeaderChecksum } from '../checksum';
import type { Result } from '../result';
import type {
  BaseLayer,
  DecodeCarrierKind,
  DecodeLayerContext,
  ProtocolTables,
  PseudoIPInfo,
} from './definition';

export function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

export function formatSpacedHexBytes(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return parts.join(' ');
}

export function computePseudoChecksum(
  ip: PseudoIPInfo,
  protocol: number,
  segment: Uint8Array,
): Result<number> {
  return ip.version === 4
    ? ipv4PseudoHeaderChecksum({
        srcIp: ip.srcIp,
        dstIp: ip.dstIp,
        protocol,
        segment,
      })
    : ipv6PseudoHeaderChecksum({
        srcIp: ip.srcIp,
        dstIp: ip.dstIp,
        nextHeader: protocol,
        segment,
      });
}

interface ChildContextParams {
  readonly carrier: DecodeCarrierKind;
  readonly enclosingLabel: string;
  readonly dispatchedValue?: number;
  readonly etherTypeParentKind?: 'link' | 'tunnel';
  readonly vlanDepth?: number;
  readonly tunnelDepth?: number;
  readonly ip?: PseudoIPInfo;
  readonly tcpDataOffsetAuto?: boolean;
  readonly tcpDataOffsetValue?: number;
}

/**
 * Creates a generic `DecodeLayerContext` backed by a registry's `ProtocolTables`.
 * Every carrier dispatches to upper layers strictly through the registry tables.
 */
export function createDecodeContext<L extends BaseLayer>(
  tables: ProtocolTables<L>,
  notes: string[],
  params: ChildContextParams,
): DecodeLayerContext<L> {
  const makeChild = (next: ChildContextParams): DecodeLayerContext<L> =>
    createDecodeContext(tables, notes, next);

  return {
    carrier: params.carrier,
    enclosingLabel: params.enclosingLabel,
    dispatchedValue: params.dispatchedValue,
    etherTypeParentKind: params.etherTypeParentKind ?? 'link',
    vlanDepth: params.vlanDepth ?? 0,
    tunnelDepth: params.tunnelDepth ?? 0,
    ip: params.ip,
    tcpDataOffsetAuto: params.tcpDataOffsetAuto,
    tcpDataOffsetValue: params.tcpDataOffsetValue,
    notes,
    tables,

    decodeByEtherType(bytes, offset, etherType, opts) {
      const vlanDepth = opts?.vlanDepth ?? 0;
      const tunnelDepth = opts?.tunnelDepth ?? 0;
      const parentKind = opts?.parentKind ?? 'link';
      const def = tables.byEtherType.get(etherType);

      if (!def) {
        const label = vlanDepth === 0 && parentKind === 'tunnel' ? 'GRE Protocol Type' : 'EtherType';
        notes.push(
          `${label} 0x${etherType.toString(16).padStart(4, '0')} is not decoded into a layer; remaining bytes kept as Payload.`,
        );
        return { layers: [], payload: bytes.slice(offset) };
      }

      const enclosing =
        vlanDepth > 0 ? 'VLAN tag' : parentKind === 'tunnel' ? 'GRE' : 'Ethernet II';

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'etherType',
          enclosingLabel: enclosing,
          dispatchedValue: etherType,
          etherTypeParentKind: parentKind,
          vlanDepth,
          tunnelDepth,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },

    decodeByGreProtocol(bytes, offset, protocolType, tunnelDepth) {
      const def = tables.byGreProtocolType.get(protocolType);
      if (!def) {
        notes.push(
          `GRE Protocol Type 0x${protocolType.toString(16).padStart(4, '0')} is not decoded into a layer; remaining bytes kept as Payload.`,
        );
        return { layers: [], payload: bytes.slice(offset) };
      }

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'greProtocol',
          enclosingLabel: 'GRE',
          dispatchedValue: protocolType,
          etherTypeParentKind: 'tunnel',
          vlanDepth: 0,
          tunnelDepth,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },

    decodeByIPv4Protocol(bytes, offset, protocol, ip, tunnelDepth) {
      const def = tables.byIPv4Protocol.get(protocol);
      if (!def) {
        notes.push(
          `IPv4 Protocol ${protocol} is not decoded into a layer; remaining bytes kept as Payload.`,
        );
        return { layers: [], payload: bytes.slice(offset) };
      }

      const remaining = bytes.length - offset;
      if (remaining < def.minHeaderLength) {
        notes.push(
          `Upper-layer header for IPv4 Protocol ${protocol} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
        );
        return { layers: [], payload: bytes.slice(offset) };
      }

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'ipv4Protocol',
          enclosingLabel: `Protocol ${protocol}`,
          dispatchedValue: protocol,
          tunnelDepth,
          ip,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },

    decodeByIPv6NextHeader(bytes, offset, nextHeader, ip, tunnelDepth) {
      const def = tables.byIPv6NextHeader.get(nextHeader);
      if (!def) {
        notes.push(
          `IPv6 Next Header ${nextHeader} is not decoded into a layer; remaining bytes kept as Payload.`,
        );
        return { layers: [], payload: bytes.slice(offset) };
      }

      const remaining = bytes.length - offset;
      if (remaining < def.minHeaderLength) {
        notes.push(
          `Upper-layer header for IPv6 Next Header ${nextHeader} is truncated (${remaining} bytes); remaining bytes kept as Payload.`,
        );
        return { layers: [], payload: bytes.slice(offset) };
      }

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'ipv6NextHeader',
          enclosingLabel: `Protocol ${nextHeader}`,
          dispatchedValue: nextHeader,
          tunnelDepth,
          ip,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },

    decodeByUdpPort(bytes, offset, dstPort, tunnelDepth) {
      const def = tables.byUdpPort.get(dstPort);
      if (!def) {
        return { layers: [], payload: bytes.slice(offset) };
      }

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'udpPort',
          enclosingLabel: `UDP port ${dstPort}`,
          dispatchedValue: dstPort,
          tunnelDepth,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },

    decodeByTcpPort(bytes, offset, srcPort, dstPort, opts) {
      const def = tables.byTcpPort.get(dstPort) ?? tables.byTcpPort.get(srcPort);
      if (!def) {
        return { layers: [], payload: bytes.slice(offset) };
      }

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'tcpPort',
          enclosingLabel: `TCP port ${dstPort}`,
          dispatchedValue: tables.byTcpPort.has(dstPort) ? dstPort : srcPort,
          tcpDataOffsetAuto: opts.dataOffsetAuto,
          tcpDataOffsetValue: opts.dataOffsetValue,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },

    decodeLinkFrame(bytes, offset, tunnelDepth, enclosingLabel) {
      const def = tables.linkFrameLayer;
      if (!def) {
        return { layers: [], payload: bytes.slice(offset) };
      }

      const decoded = def.decode(
        bytes,
        offset,
        makeChild({
          carrier: 'linkFrame',
          enclosingLabel,
          tunnelDepth,
        }) as unknown as DecodeLayerContext<BaseLayer>,
      );

      if (!decoded) {
        return { layers: [], payload: bytes.slice(offset) };
      }
      return {
        layers: decoded.layers as readonly L[],
        payload: decoded.payload,
      };
    },
  };
}
