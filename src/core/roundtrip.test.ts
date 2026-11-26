import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from './bytes';
import { manualValue } from './layers/types';
import {
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultIPv4,
  createDefaultTCP,
  createDefaultUDP,
  createPresets,
} from './presets';
import { analyzeBuiltBytesRoundTrip, analyzeDecodeRoundTrip } from './roundtrip';

describe('analyzeDecodeRoundTrip', () => {
  it('reports reproducible for every built-in preset', () => {
    for (const preset of createPresets()) {
      expect(analyzeDecodeRoundTrip(preset.layers, preset.payloadBytes)).toEqual({
        kind: 'reproducible',
      });
    }
  });

  it('reports reproducible for IP-in-IP (Ethernet -> IPv4 -> IPv4 -> UDP) and Raw IPv4 stacks', () => {
    const ipInIp = [
      createDefaultEthernet(),
      createDefaultIPv4(),
      createDefaultIPv4(),
      createDefaultUDP(),
    ];
    expect(analyzeDecodeRoundTrip(ipInIp, encodeUtf8('tunnel-ok'))).toEqual({
      kind: 'reproducible',
    });

    const rawIpv4 = [createDefaultIPv4(), createDefaultUDP()];
    expect(analyzeDecodeRoundTrip(rawIpv4, encodeUtf8('raw-ip'))).toEqual({
      kind: 'reproducible',
    });
  });

  it('reports differs for Ethernet -> IPv4 -> UDP -> Ethernet -> IPv4 -> TCP', () => {
    const layers = [
      createDefaultEthernet(),
      createDefaultIPv4(),
      createDefaultUDP(),
      createDefaultEthernet(),
      createDefaultIPv4(),
      createDefaultTCP(),
    ];
    // Inner headers: Ethernet (14B) + IPv4 (20B) + TCP (20B) = 54B payload inside outer UDP
    expect(analyzeDecodeRoundTrip(layers, new Uint8Array(0))).toEqual({
      kind: 'differs',
      decodedLayerTypes: ['ethernet', 'ipv4', 'udp'],
      decodedPayloadLength: 54,
    });
  });

  it('reports unsupported-start for stacks not starting with Ethernet II or IPv4', () => {
    const tcpBgp = [
      { ...createDefaultTCP(), dstPort: 80 },
      createDefaultBGP(),
    ];
    expect(analyzeDecodeRoundTrip(tcpBgp, new Uint8Array(0))).toEqual({
      kind: 'unsupported-start',
      outerLayerType: 'tcp',
    });

    const udpIpv4 = [createDefaultUDP(), createDefaultIPv4()];
    expect(analyzeDecodeRoundTrip(udpIpv4, new Uint8Array(0))).toEqual({
      kind: 'unsupported-start',
      outerLayerType: 'udp',
    });

    // Payload-only packet with no headers
    expect(analyzeDecodeRoundTrip([], encodeUtf8('raw-bytes'))).toEqual({
      kind: 'unsupported-start',
      outerLayerType: null,
    });
  });

  it('reports differs for Ethernet -> IPv4 -> TCP(dst 80) -> BGP because BGP decoding only triggers on port 179', () => {
    const layers = [
      createDefaultEthernet(),
      createDefaultIPv4(),
      { ...createDefaultTCP(), srcPort: 50000, dstPort: 80 },
      createDefaultBGP(), // OPEN = 29B
    ];
    expect(analyzeDecodeRoundTrip(layers, new Uint8Array(0))).toEqual({
      kind: 'differs',
      decodedLayerTypes: ['ethernet', 'ipv4', 'tcp'],
      decodedPayloadLength: 29,
    });
  });

  it('reports differs when payload length changes on decode (e.g. Ethernet with manual EtherType or truncated IPv4 Total Length)', () => {
    const manualEtherType = [
      { ...createDefaultEthernet(), etherType: manualValue(0x88b5) },
      createDefaultIPv4(),
    ];
    expect(analyzeDecodeRoundTrip(manualEtherType, new Uint8Array(0))).toEqual({
      kind: 'differs',
      decodedLayerTypes: ['ethernet'],
      decodedPayloadLength: 20,
    });

    const truncatedTotalLength = [
      createDefaultEthernet(),
      { ...createDefaultIPv4(), totalLength: manualValue(20) },
      createDefaultUDP(),
    ];
    expect(analyzeDecodeRoundTrip(truncatedTotalLength, encodeUtf8('hi'))).toEqual({
      kind: 'differs',
      decodedLayerTypes: ['ethernet', 'ipv4'],
      decodedPayloadLength: 0,
    });
  });

  it('reports not-built for stacks with build errors (including unsupported outer layers) and for empty packets', () => {
    const brokenEthIp = [
      createDefaultEthernet(),
      { ...createDefaultIPv4(), ttl: 999 },
    ];
    expect(analyzeDecodeRoundTrip(brokenEthIp, new Uint8Array(0))).toEqual({
      kind: 'not-built',
    });

    const brokenUdpStart = [{ ...createDefaultUDP(), dstPort: 70000 }];
    expect(analyzeDecodeRoundTrip(brokenUdpStart, new Uint8Array(0))).toEqual({
      kind: 'not-built',
    });

    expect(analyzeDecodeRoundTrip([], new Uint8Array(0))).toEqual({
      kind: 'not-built',
    });
  });

  it('returns empty differs with decodedPayloadLength 0 if decodePacket fails on built bytes', () => {
    const ethOnly = [createDefaultEthernet()];
    // Truncated 4-byte buffer cannot decode as 14-byte Ethernet II header
    expect(analyzeBuiltBytesRoundTrip(ethOnly, 0, new Uint8Array([1, 2, 3, 4]))).toEqual({
      kind: 'differs',
      decodedLayerTypes: [],
      decodedPayloadLength: 0,
    });
  });
});
