import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from '../bytes';
import {
  buildGREFieldSpans,
  encodeGRE,
  getGREHeaderLength,
  GRE_PROTOCOL_TEB,
  greProtocolTypeForUpperLayer,
} from './gre';
import { autoValue, manualValue, type GRELayer } from './types';

function makeGRE(overrides: Partial<GRELayer> = {}): GRELayer {
  return {
    type: 'gre',
    checksumPresent: false,
    keyPresent: false,
    sequencePresent: false,
    version: autoValue(),
    protocolType: autoValue(),
    checksum: autoValue(),
    key: 0,
    sequenceNumber: 0,
    ...overrides,
  };
}

describe('GRE encoder (RFC 2784 / RFC 2890)', () => {
  it('computes header lengths (4/8/12/16B), flag words, and contiguous bit spans for all 8 C/K/S combinations', () => {
    const combos: ReadonlyArray<{
      readonly c: boolean;
      readonly k: boolean;
      readonly s: boolean;
      readonly expectedLen: number;
      readonly expectedFlagsHi: number;
    }> = [
      { c: false, k: false, s: false, expectedLen: 4, expectedFlagsHi: 0x00 },
      { c: false, k: false, s: true, expectedLen: 8, expectedFlagsHi: 0x10 },
      { c: false, k: true, s: false, expectedLen: 8, expectedFlagsHi: 0x20 },
      { c: false, k: true, s: true, expectedLen: 12, expectedFlagsHi: 0x30 },
      { c: true, k: false, s: false, expectedLen: 8, expectedFlagsHi: 0x80 },
      { c: true, k: false, s: true, expectedLen: 12, expectedFlagsHi: 0x90 },
      { c: true, k: true, s: false, expectedLen: 12, expectedFlagsHi: 0xa0 },
      { c: true, k: true, s: true, expectedLen: 16, expectedFlagsHi: 0xb0 },
    ];

    for (const combo of combos) {
      const layer = makeGRE({
        checksumPresent: combo.c,
        keyPresent: combo.k,
        sequencePresent: combo.s,
        key: 0x11223344,
        sequenceNumber: 0x55667788,
      });

      expect(getGREHeaderLength(layer)).toBe(combo.expectedLen);

      const spans = buildGREFieldSpans(layer);
      let bitCursor = 0;
      for (const span of spans) {
        expect(span.bitOffset).toBe(bitCursor);
        expect(span.bitLength).toBeGreaterThan(0);
        bitCursor += span.bitLength;
      }
      expect(bitCursor).toBe(combo.expectedLen * 8);

      const res = encodeGRE(layer, {
        layerIndex: 1,
        upperLayerType: 'ipv4',
        upperBytes: new Uint8Array([0x45, 0x00]),
      });
      expect(res.ok).toBe(true);
      if (!res.ok) continue;

      expect(res.bytes).toHaveLength(combo.expectedLen);
      expect(res.bytes[0]).toBe(combo.expectedFlagsHi);
      expect(res.bytes[1]).toBe(0x00); // Reserved0=0, Version=0
      expect(res.bytes[2]).toBe(0x08);
      expect(res.bytes[3]).toBe(0x00);
      expect(res.warnings).toHaveLength(0);
    }
  });

  it('auto-detects Protocol Type for IPv4, IPv6, Ethernet (GRETAP 0x6558), ARP, and VLAN, and warns on unsupported upper layers', () => {
    expect(greProtocolTypeForUpperLayer('ipv4')).toBe(0x0800);
    expect(greProtocolTypeForUpperLayer('ipv6')).toBe(0x86dd);
    expect(greProtocolTypeForUpperLayer('ethernet')).toBe(GRE_PROTOCOL_TEB);
    expect(greProtocolTypeForUpperLayer('arp')).toBe(0x0806);
    expect(greProtocolTypeForUpperLayer('vlan')).toBe(0x8100);
    expect(greProtocolTypeForUpperLayer('udp')).toBeNull();
    expect(greProtocolTypeForUpperLayer(null)).toBeNull();

    const gretap = encodeGRE(makeGRE(), {
      layerIndex: 1,
      upperLayerType: 'ethernet',
      upperBytes: new Uint8Array(14),
    });
    expect(gretap.ok).toBe(true);
    if (gretap.ok) {
      expect(gretap.bytes).toEqual(new Uint8Array([0x00, 0x00, 0x65, 0x58]));
      expect(gretap.resolvedAutoValues.protocolType).toBe(0x6558);
      expect(gretap.warnings).toHaveLength(0);
    }

    const fallback = encodeGRE(makeGRE(), {
      layerIndex: 1,
      upperLayerType: null,
      upperBytes: new Uint8Array(0),
    });
    expect(fallback.ok).toBe(true);
    if (fallback.ok) {
      expect(fallback.bytes).toEqual(new Uint8Array([0x00, 0x00, 0x08, 0x00]));
      expect(fallback.warnings.some((w) => w.fieldId === 'protocolType')).toBe(true);
    }
  });

  it('computes RFC 2784 §2.5 checksum over the GRE header (with Key/Sequence) and odd-length payload', () => {
    // Hand-verified RFC 2784 §2.5 checksum:
    //   GRE header (16B, C=1, K=1, S=1, Ver=0, Proto=0x0800, Key=0x01020304, Seq=0x00000007):
    //   words = 0xb000 + 0x0800 + 0x0000 (csum) + 0x0000 (res1)
    //         + 0x0102 + 0x0304 + 0x0000 + 0x0007
    //   payload "abc" (3 bytes, padded with 0x00): 0x6162 + 0x6300
    //   sum:
    //     b000 + 0800 = b800
    //     b800 + 0102 = b902
    //     b902 + 0304 = bc06
    //     bc06 + 0007 = bc0d
    //     bc0d + 6162 = 11d6f -> fold: 1d70
    //     1d70 + 6300 = 8070
    //   ~0x8070 & 0xffff = 0x7f8f
    const res = encodeGRE(
      makeGRE({
        checksumPresent: true,
        keyPresent: true,
        sequencePresent: true,
        key: 0x01020304,
        sequenceNumber: 7,
      }),
      {
        layerIndex: 1,
        upperLayerType: 'ipv4',
        upperBytes: encodeUtf8('abc'),
      },
    );
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.bytes).toEqual(
      new Uint8Array([
        0xb0, 0x00, 0x08, 0x00, // C=1, K=1, S=1, Ver=0, Proto=0x0800
        0x7f, 0x8f, 0x00, 0x00, // Checksum=0x7f8f, Reserved1=0x0000
        0x01, 0x02, 0x03, 0x04, // Key
        0x00, 0x00, 0x00, 0x07, // Sequence Number
      ]),
    );
    expect(res.resolvedAutoValues.checksum).toBe(0x7f8f);
    expect(res.warnings).toHaveLength(0);
  });

  it('warns on non-zero GRE Version and manual checksum/protocol overrides, and validates bounds only on active optional fields', () => {
    const v1 = encodeGRE(makeGRE({ version: manualValue(1) }), {
      layerIndex: 1,
      upperLayerType: 'ipv4',
      upperBytes: new Uint8Array(0),
    });
    expect(v1.ok).toBe(true);
    if (v1.ok) {
      expect(v1.bytes).toEqual(new Uint8Array([0x00, 0x01, 0x08, 0x00]));
      expect(v1.warnings.some((w) => w.fieldId === 'version' && w.message.includes('RFC 2784'))).toBe(
        true,
      );
    }

    const manualCsum = encodeGRE(
      makeGRE({ checksumPresent: true, checksum: manualValue(0xdead) }),
      {
        layerIndex: 1,
        upperLayerType: 'ipv4',
        upperBytes: new Uint8Array(0),
      },
    );
    expect(manualCsum.ok).toBe(true);
    if (manualCsum.ok) {
      expect(manualCsum.bytes.slice(4, 6)).toEqual(new Uint8Array([0xde, 0xad]));
      expect(manualCsum.warnings.some((w) => w.fieldId === 'checksum')).toBe(true);
    }

    // Hidden (inactive) optional fields do not block encoding
    const inactiveInvalid = encodeGRE(
      makeGRE({
        checksumPresent: false,
        keyPresent: false,
        sequencePresent: false,
        checksum: manualValue(99999),
        key: -1,
        sequenceNumber: 0x1_0000_0000,
      }),
      {
        layerIndex: 1,
        upperLayerType: 'ipv4',
        upperBytes: new Uint8Array(0),
      },
    );
    expect(inactiveInvalid.ok).toBe(true);

    // Out-of-range active fields produce field-scoped errors
    const activeInvalid = encodeGRE(
      makeGRE({
        checksumPresent: true,
        keyPresent: true,
        sequencePresent: true,
        version: manualValue(8),
        protocolType: manualValue(0x10000),
        checksum: manualValue(0x10000),
        key: -1,
        sequenceNumber: 0x1_0000_0000,
      }),
      {
        layerIndex: 2,
        upperLayerType: 'ipv4',
        upperBytes: new Uint8Array(0),
      },
    );
    expect(activeInvalid.ok).toBe(false);
    if (!activeInvalid.ok) {
      expect(activeInvalid.errors.map((e) => e.fieldId)).toEqual([
        'version',
        'protocolType',
        'checksum',
        'key',
        'sequenceNumber',
      ]);
    }
  });
});
