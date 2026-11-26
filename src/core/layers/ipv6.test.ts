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
        upperLayerType: 'udp',
        upperBytesLength: 13,
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toHaveLength(IPV6_HEADER_LENGTH);
    // First 32-bit word: Version=6 (0x6), Traffic Class=0xab, Flow Label=0xcdef1 -> 0x6abcdef1
    expect(result.bytes.slice(0, 8)).toEqual(
      new Uint8Array([0x6a, 0xbc, 0xde, 0xf1, 0x00, 0x0d, 0x11, 0x80]),
    );
    expect(result.bytes.slice(8, 24)).toEqual(
      new Uint8Array([
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      ]),
    );
    expect(result.bytes.slice(24, 40)).toEqual(
      new Uint8Array([
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
      ]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({
      payloadLength: 13,
      nextHeader: 17,
    });

    // Field spans must be contiguous across all 320 bits (40 bytes)
    let cursor = 0;
    for (const span of IPV6_FIELD_SPANS) {
      expect(span.bitOffset).toBe(cursor);
      cursor += span.bitLength;
    }
    expect(cursor).toBe(IPV6_HEADER_LENGTH * 8);
  });

  it('auto-selects Next Header for TCP (6), UDP (17), ICMPv6 (58), IPv4 (4), and IPv6 (41)', () => {
    const tcp = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'tcp',
      upperBytesLength: 20,
    });
    const udp = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 8,
    });
    const icmpv6 = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'icmpv6',
      upperBytesLength: 8,
    });
    const ipv4 = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'ipv4',
      upperBytesLength: 20,
    });
    const ipv6 = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'ipv6',
      upperBytesLength: 40,
    });

    expect(tcp.ok && tcp.bytes[6]).toBe(6);
    expect(udp.ok && udp.bytes[6]).toBe(17);
    expect(icmpv6.ok && icmpv6.bytes[6]).toBe(58);
    expect(ipv4.ok && ipv4.bytes[6]).toBe(4);
    expect(ipv6.ok && ipv6.bytes[6]).toBe(41);
    expect(tcp.ok && tcp.warnings).toEqual([]);
    expect(udp.ok && udp.warnings).toEqual([]);
    expect(icmpv6.ok && icmpv6.warnings).toEqual([]);
    expect(ipv4.ok && ipv4.warnings).toEqual([]);
    expect(ipv6.ok && ipv6.warnings).toEqual([]);
  });

  it('warns to use ICMPv6 when ICMPv4 sits directly above IPv6 and keeps fallback Next Header 0', () => {
    const result = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'icmp',
      upperBytesLength: 8,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes[6]).toBe(0);
    expect(result.resolvedAutoValues.nextHeader).toBe(0);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0].fieldId).toBe('nextHeader');
    expect(result.warnings[0].message).toContain('use ICMPv6');
  });

  it('warns and defaults Next Header to 0 when there is no supported upper layer', () => {
    const result = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: null,
      upperBytesLength: 4,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes[6]).toBe(0);
    expect(result.warnings.some((w) => w.fieldId === 'nextHeader')).toBe(true);
  });

  it('validates Flow Label boundaries (0 and 0xfffff succeed; 0x100000 and -1 fail)', () => {
    const min = encodeIPv6(makeBaseIPv6({ flowLabel: 0 }), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 8,
    });
    expect(min.ok).toBe(true);

    const max = encodeIPv6(makeBaseIPv6({ flowLabel: 0xfffff }), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 8,
    });
    expect(max.ok).toBe(true);
    if (max.ok) {
      expect(max.bytes.slice(0, 4)).toEqual(new Uint8Array([0x60, 0x0f, 0xff, 0xff]));
    }

    const overflow = encodeIPv6(makeBaseIPv6({ flowLabel: 0x100000 }), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 8,
    });
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.fieldId === 'flowLabel')).toBe(true);
    }

    const negative = encodeIPv6(makeBaseIPv6({ flowLabel: -1 }), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 8,
    });
    expect(negative.ok).toBe(false);
  });

  it('validates Payload Length boundaries (65535 succeeds; 65536 fails)', () => {
    const okMax = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 65535,
    });
    expect(okMax.ok).toBe(true);
    if (okMax.ok) {
      expect(okMax.bytes.slice(4, 6)).toEqual(new Uint8Array([0xff, 0xff]));
    }

    const overflow = encodeIPv6(makeBaseIPv6(), {
      layerIndex: 0,
      upperLayerType: 'udp',
      upperBytesLength: 65536,
    });
    expect(overflow.ok).toBe(false);
    if (!overflow.ok) {
      expect(overflow.errors.some((e) => e.fieldId === 'payloadLength')).toBe(true);
    }
  });

  it('prefers manual Payload Length and Next Header and emits warnings on mismatch', () => {
    const result = encodeIPv6(
      makeBaseIPv6({
        payloadLength: manualValue(100),
        nextHeader: manualValue(60),
      }),
      {
        layerIndex: 0,
        upperLayerType: 'udp',
        upperBytesLength: 8,
      },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(4, 6)).toEqual(new Uint8Array([0x00, 100]));
    expect(result.bytes[6]).toBe(60);
    expect(result.warnings.map((w) => w.fieldId)).toEqual(['payloadLength', 'nextHeader']);
  });

  it('reports field-level errors for out-of-range fields and invalid IPv6 addresses', () => {
    const result = encodeIPv6(
      makeBaseIPv6({
        trafficClass: 256,
        flowLabel: 0x100000,
        hopLimit: -1,
        srcIp: 'fe80::1%eth0',
        dstIp: '2001::db8::1',
        payloadLength: manualValue(70000),
        nextHeader: manualValue(300),
      }),
      {
        layerIndex: 0,
        upperLayerType: 'udp',
        upperBytesLength: 8,
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'trafficClass',
      'flowLabel',
      'hopLimit',
      'srcIp',
      'dstIp',
      'payloadLength',
      'nextHeader',
    ]);
  });
});
