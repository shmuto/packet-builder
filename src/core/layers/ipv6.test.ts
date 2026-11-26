import { describe, expect, it } from 'vitest';
import { encodeIPv6, IPV6_FIELD_SPANS, IPV6_HEADER_LENGTH } from './ipv6';
import { autoValue, manualValue, type IPv6Layer } from './types';

function makeBaseIPv6(overrides: Partial<IPv6Layer> = {}): IPv6Layer {
  return {
    type: 'ipv6',
    trafficClass: 0,
    flowLabel: 0,
    payloadLength: autoValue(),
    nextHeader: autoValue(),
    hopLimit: 64,
    srcIp: '2001:db8::1',
    dstIp: '2001:db8::2',
    ...overrides,
  };
}

describe('encodeIPv6', () => {
  it('encodes a 40-byte fixed IPv6 header and packs Version(4b)/Traffic Class(8b)/Flow Label(20b)', () => {
    const result = encodeIPv6(
      makeBaseIPv6({
        trafficClass: 0xab,
        flowLabel: 0xcdef1,
        hopLimit: 128,
      }),
      {
        layerIndex: 0,
        upperLayerType: 'tcp',
        upperBytesLength: 20,
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toHaveLength(IPV6_HEADER_LENGTH);
    expect(result.bytes.slice(0, 8)).toEqual(
      new Uint8Array([0x6a, 0xbc, 0xde, 0xf1, 0x00, 0x14, 0x06, 0x80]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({
      payloadLength: 20,
      nextHeader: 6,
    });

    let cursor = 0;
    for (const span of IPV6_FIELD_SPANS) {
      expect(span.bitOffset).toBe(cursor);
      cursor += span.bitLength;
    }
    expect(cursor).toBe(IPV6_HEADER_LENGTH * 8);
  });

  it('auto-selects Next Header for TCP (6), IPv4 (4), and IPv6 (41)', () => {
    const tcp = encodeIPv6(makeBaseIPv6(), { layerIndex: 0, upperLayerType: 'tcp', upperBytesLength: 20 });
    const ipv4 = encodeIPv6(makeBaseIPv6(), { layerIndex: 0, upperLayerType: 'ipv4', upperBytesLength: 20 });
    const ipv6 = encodeIPv6(makeBaseIPv6(), { layerIndex: 0, upperLayerType: 'ipv6', upperBytesLength: 40 });

    expect(tcp.ok && tcp.bytes[6]).toBe(6);
    expect(ipv4.ok && ipv4.bytes[6]).toBe(4);
    expect(ipv6.ok && ipv6.bytes[6]).toBe(41);
  });

  it('validates Flow Label, Payload Length, and manual overrides', () => {
    const overflow = encodeIPv6(makeBaseIPv6({ flowLabel: 0x100000 }), {
      layerIndex: 0,
      upperLayerType: 'tcp',
      upperBytesLength: 65536,
    });
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.map((e) => e.fieldId)).toEqual(['flowLabel', 'payloadLength']);
    }

    const manual = encodeIPv6(
      makeBaseIPv6({ payloadLength: manualValue(100), nextHeader: manualValue(60) }),
      { layerIndex: 0, upperLayerType: 'tcp', upperBytesLength: 20 },
    );
    expect(manual.ok).toBe(true);
    if (manual.ok) {
      expect(manual.warnings.map((w) => w.fieldId)).toEqual(['payloadLength', 'nextHeader']);
    }
  });
});
