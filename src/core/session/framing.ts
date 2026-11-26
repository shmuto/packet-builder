import { concatBytes, parseIPv4, parseIPv6 } from '../bytes';
import { encodeEthernet } from '../layers/ethernet';
import { encodeIPv4 } from '../layers/ipv4';
import { encodeIPv6 } from '../layers/ipv6';
import { encodeTCP } from '../layers/tcp';
import {
  autoValue,
  type EthernetLayer,
  type IPv4Layer,
  type IPv6Layer,
  type TCPFlags,
  type TCPLayer,
  type TCPOption,
} from '../layers/types';
import type { IPPseudoContext } from '../layers/udp';
import type { RouterConfig, RouterId, SessionType } from './types';

export const BGP_TCP_PORT = 179;
export const CLIENT_TCP_PORT = 49152;
export const TCP_MSS_VALUE = 1460;
export const TCP_WINDOW_SIZE = 65535;

export interface TcpConnectionTracker {
  readonly ipVersion: 4 | 6;
  readonly sessionType: SessionType;
  readonly portA: number;
  readonly portB: number;
  seqA: number;
  seqB: number;
  ipIdA: number;
  ipIdB: number;
}

export function isIPv6Address(addr: string): boolean {
  return addr.includes(':');
}

export function createTcpTracker(
  routerA: RouterConfig,
  routerB: RouterConfig,
  sessionType: SessionType,
): TcpConnectionTracker {
  const aIsV6 = isIPv6Address(routerA.peeringAddress);
  const bIsV6 = isIPv6Address(routerB.peeringAddress);
  if (aIsV6 !== bIsV6) {
    throw new Error(
      `Peering address IP version mismatch: ${routerA.peeringAddress} vs ${routerB.peeringAddress}.`,
    );
  }
  return {
    ipVersion: aIsV6 ? 6 : 4,
    sessionType,
    portA: CLIENT_TCP_PORT,
    portB: BGP_TCP_PORT,
    seqA: 1000,
    seqB: 2000,
    ipIdA: 1,
    ipIdB: 1,
  };
}

export interface BuildTcpFrameOptions {
  readonly from: RouterId;
  readonly sender: RouterConfig;
  readonly receiver: RouterConfig;
  readonly tracker: TcpConnectionTracker;
  readonly flags: Partial<TCPFlags>;
  readonly options?: readonly TCPOption[];
  readonly payload?: Uint8Array;
}

export interface BuiltTcpFrame {
  readonly frameBytes: Uint8Array;
  readonly payloadOffset: number;
  readonly seq: number;
  readonly ack: number;
}

/**
 * Encodes a complete Ethernet II + IPv4/IPv6 + TCP (+ optional BGP payload) frame
 * using the existing core layer encoders and advances the sender's TCP sequence number.
 */
export function buildTcpFrame({
  from,
  sender,
  receiver,
  tracker,
  flags,
  options = [],
  payload = new Uint8Array(0),
}: BuildTcpFrameOptions): BuiltTcpFrame {
  const isFromA = from === 'A';
  const srcPort = isFromA ? tracker.portA : tracker.portB;
  const dstPort = isFromA ? tracker.portB : tracker.portA;
  const seq = isFromA ? tracker.seqA : tracker.seqB;
  const ack = flags.ack ? (isFromA ? tracker.seqB : tracker.seqA) : 0;

  const fullFlags: TCPFlags = {
    cwr: false,
    ece: false,
    urg: false,
    ack: false,
    psh: false,
    rst: false,
    syn: false,
    fin: false,
    ...flags,
  };

  let ipPseudo: IPPseudoContext;
  if (tracker.ipVersion === 4) {
    const srcRes = parseIPv4(sender.peeringAddress);
    const dstRes = parseIPv4(receiver.peeringAddress);
    if (!srcRes.ok || !dstRes.ok) {
      throw new Error(
        `Invalid IPv4 peering address (${sender.peeringAddress} -> ${receiver.peeringAddress}).`,
      );
    }
    ipPseudo = { status: 'valid', version: 4, srcIp: srcRes.value, dstIp: dstRes.value };
  } else {
    const srcRes = parseIPv6(sender.peeringAddress);
    const dstRes = parseIPv6(receiver.peeringAddress);
    if (!srcRes.ok || !dstRes.ok) {
      throw new Error(
        `Invalid IPv6 peering address (${sender.peeringAddress} -> ${receiver.peeringAddress}).`,
      );
    }
    ipPseudo = { status: 'valid', version: 6, srcIp: srcRes.value, dstIp: dstRes.value };
  }

  const tcpLayer: TCPLayer = {
    type: 'tcp',
    srcPort,
    dstPort,
    seqNumber: seq,
    ackNumber: ack,
    dataOffset: autoValue(),
    flags: fullFlags,
    windowSize: TCP_WINDOW_SIZE,
    checksum: autoValue(),
    urgentPointer: 0,
    options,
  };

  const tcpRes = encodeTCP(tcpLayer, {
    layerIndex: 2,
    ip: ipPseudo,
    upperBytes: payload,
  });
  if (!tcpRes.ok) {
    throw new Error(`TCP encode failed: ${tcpRes.errors.map((e) => e.message).join('; ')}`);
  }

  const transportBytes = concatBytes(tcpRes.bytes, payload);
  const ttl = tracker.sessionType === 'ebgp' ? 1 : 64;

  let ipBytes: Uint8Array;
  let nextLayerType: 'ipv4' | 'ipv6';
  if (tracker.ipVersion === 4) {
    const ipId = isFromA ? tracker.ipIdA++ : tracker.ipIdB++;
    const ipv4Layer: IPv4Layer = {
      type: 'ipv4',
      ihl: autoValue(),
      tos: 0xc0, // CS6 Internetwork Control (standard DSCP for BGP)
      totalLength: autoValue(),
      identification: ipId & 0xffff,
      flags: { reserved: false, df: true, mf: false },
      fragmentOffset: 0,
      ttl,
      protocol: autoValue(),
      headerChecksum: autoValue(),
      srcIp: sender.peeringAddress,
      dstIp: receiver.peeringAddress,
      options: [],
    };
    const ipv4Res = encodeIPv4(ipv4Layer, {
      layerIndex: 1,
      upperLayerType: 'tcp',
      upperBytesLength: transportBytes.length,
    });
    if (!ipv4Res.ok) {
      throw new Error(`IPv4 encode failed: ${ipv4Res.errors.map((e) => e.message).join('; ')}`);
    }
    ipBytes = ipv4Res.bytes;
    nextLayerType = 'ipv4';
  } else {
    const ipv6Layer: IPv6Layer = {
      type: 'ipv6',
      trafficClass: 0xc0,
      flowLabel: 0,
      payloadLength: autoValue(),
      nextHeader: autoValue(),
      hopLimit: ttl,
      srcIp: sender.peeringAddress,
      dstIp: receiver.peeringAddress,
    };
    const ipv6Res = encodeIPv6(ipv6Layer, {
      layerIndex: 1,
      upperLayerType: 'tcp',
      upperBytesLength: transportBytes.length,
    });
    if (!ipv6Res.ok) {
      throw new Error(`IPv6 encode failed: ${ipv6Res.errors.map((e) => e.message).join('; ')}`);
    }
    ipBytes = ipv6Res.bytes;
    nextLayerType = 'ipv6';
  }

  const ethLayer: EthernetLayer = {
    type: 'ethernet',
    dstMac: receiver.mac,
    srcMac: sender.mac,
    etherType: autoValue(),
  };
  const ethRes = encodeEthernet(ethLayer, {
    layerIndex: 0,
    upperLayerType: nextLayerType,
    upperNextLayerType: 'tcp',
    upperBytesLength: ipBytes.length + transportBytes.length,
  });
  if (!ethRes.ok) {
    throw new Error(`Ethernet encode failed: ${ethRes.errors.map((e) => e.message).join('; ')}`);
  }

  // Advance TCP sequence number: SYN and FIN each consume 1 sequence number, plus payload bytes
  const seqDelta = payload.length + (fullFlags.syn ? 1 : 0) + (fullFlags.fin ? 1 : 0);
  if (isFromA) {
    tracker.seqA = (tracker.seqA + seqDelta) >>> 0;
  } else {
    tracker.seqB = (tracker.seqB + seqDelta) >>> 0;
  }

  const frameBytes = concatBytes(ethRes.bytes, ipBytes, transportBytes);
  const payloadOffset = ethRes.bytes.length + ipBytes.length + tcpRes.bytes.length;

  return { frameBytes, payloadOffset, seq, ack };
}
