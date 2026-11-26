import { describe, expect, it } from 'vitest';
import { internetChecksum } from '../checksum';
import { encodeIPv4 } from './ipv4';
import { autoValue, manualValue, type IPv4Layer } from './types';

function makeBaseIPv4(overrides: Partial<IPv4Layer> = {}): IPv4Layer {
  return {
    type: 'ipv4',
    ihl: autoValue(),
    tos: 0,
    totalLength: autoValue(),
    identification: 0x1234,
    flags: { reserved: false, df: true, mf: false },
    fragmentOffset: 0,
    ttl: 64,
    protocol: autoValue(),
    headerChecksum: autoValue(),
    srcIp: '192.168.0.1',
    dstIp: '192.168.0.2',
    ...overrides,
  };
}

describe('encodeIPv4', () => {
  it('encodes a 20-byte IPv4 header for TCP with a valid RFC 1071 checksum', () => {
    const result = encodeIPv4(makeBaseIPv4(), {
      layerIndex: 0,
      upperLayerType: 'tcp',
      upperBytesLength: 20,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.length).toBe(20);
    expect(result.bytes[0]).toBe(0x45);
    expect(result.bytes[9]).toBe(6); // TCP
    expect(internetChecksum(result.bytes)).toBe(0);
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues.ihl).toBe(5);
    expect(result.resolvedAutoValues.totalLength).toBe(40);
    expect(result.resolvedAutoValues.protocol).toBe(6);
  });

  it('supports manual overrides for Total Length, Protocol, and Header Checksum with warnings', () => {
    const result = encodeIPv4(
      makeBaseIPv4({
        totalLength: manualValue(100),
        protocol: manualValue(17),
        headerChecksum: manualValue(0xdead),
        flags: { reserved: true, df: true, mf: false },
      }),
      { layerIndex: 0, upperLayerType: 'tcp', upperBytesLength: 20 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(2, 4)).toEqual(new Uint8Array([0x00, 100]));
    expect(result.bytes[9]).toBe(17);
    expect(result.bytes.slice(10, 12)).toEqual(new Uint8Array([0xde, 0xad]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual([
      'flags',
      'totalLength',
      'protocol',
      'headerChecksum',
    ]);
  });

  it('rejects out-of-range fields, invalid IP addresses, and oversized payloads', () => {
    const result = encodeIPv4(
      makeBaseIPv4({
        tos: 256,
        identification: 70000,
        fragmentOffset: 9000,
        ttl: -1,
        srcIp: 'bad',
        dstIp: '999.0.0.1',
      }),
      { layerIndex: 0, upperLayerType: 'tcp', upperBytesLength: 65530 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'tos',
      'identification',
      'fragmentOffset',
      'ttl',
      'srcIp',
      'dstIp',
      'totalLength',
    ]);
  });
});
