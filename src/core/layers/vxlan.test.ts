import { describe, expect, it } from 'vitest';
import { autoValue, manualValue, type VXLANLayer } from './types';
import {
  encodeVXLAN,
  VXLAN_FIELD_SPANS,
  VXLAN_FLAG_I,
  VXLAN_HEADER_LENGTH,
  VXLAN_MAX_VNI,
  VXLAN_PORT,
} from './vxlan';

function makeVXLAN(overrides: Partial<VXLANLayer> = {}): VXLANLayer {
  return {
    type: 'vxlan',
    flags: autoValue(),
    vni: 100,
    reserved1: 0,
    reserved2: 0,
    ...overrides,
  };
}

const validVxlanUdp = { status: 'valid' as const, srcPort: 49152, dstPort: VXLAN_PORT };

describe('VXLAN encoder (RFC 7348 §5)', () => {
  it('encodes VXLAN header with I=1, VNI 100, and zero reserved fields as 08 00 00 00 00 00 64 00 with zero warnings and contiguous 64-bit spans', () => {
    let bitCursor = 0;
    for (const span of VXLAN_FIELD_SPANS) {
      expect(span.bitOffset).toBe(bitCursor);
      expect(span.bitLength).toBeGreaterThan(0);
      bitCursor += span.bitLength;
    }
    expect(bitCursor).toBe(VXLAN_HEADER_LENGTH * 8);

    const res = encodeVXLAN(makeVXLAN({ vni: 100 }), {
      layerIndex: 3,
      udp: validVxlanUdp,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.bytes).toEqual(new Uint8Array([0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00]));
    expect(res.warnings).toHaveLength(0);
    expect(res.resolvedAutoValues).toEqual({ flags: VXLAN_FLAG_I });
  });

  it('validates VNI boundaries: 0 and 16777215 succeed, 16777216 and -1 error', () => {
    const vniMin = encodeVXLAN(makeVXLAN({ vni: 0 }), { layerIndex: 3, udp: validVxlanUdp });
    expect(vniMin.ok).toBe(true);
    if (vniMin.ok) {
      expect(vniMin.bytes).toEqual(new Uint8Array([0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
      expect(vniMin.warnings).toHaveLength(0);
    }

    const vniMax = encodeVXLAN(makeVXLAN({ vni: VXLAN_MAX_VNI }), {
      layerIndex: 3,
      udp: validVxlanUdp,
    });
    expect(vniMax.ok).toBe(true);
    if (vniMax.ok) {
      expect(vniMax.bytes).toEqual(new Uint8Array([0x08, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00]));
      expect(vniMax.warnings).toHaveLength(0);
    }

    const vniOverflow = encodeVXLAN(makeVXLAN({ vni: 16777216 }), {
      layerIndex: 3,
      udp: validVxlanUdp,
    });
    expect(vniOverflow.ok).toBe(false);
    if (!vniOverflow.ok) {
      expect(vniOverflow.errors.some((e) => e.fieldId === 'vni')).toBe(true);
    }

    const vniNegative = encodeVXLAN(makeVXLAN({ vni: -1 }), { layerIndex: 3, udp: validVxlanUdp });
    expect(vniNegative.ok).toBe(false);
    if (!vniNegative.ok) {
      expect(vniNegative.errors.some((e) => e.fieldId === 'vni')).toBe(true);
    }
  });

  it('emits non-blocking warnings for I=0, non-zero reserved bits/fields, absent UDP, and non-4789 UDP dstPort', () => {
    // 1. I-flag = 0
    const noIFlag = encodeVXLAN(makeVXLAN({ flags: manualValue(0x00) }), {
      layerIndex: 3,
      udp: validVxlanUdp,
    });
    expect(noIFlag.ok).toBe(true);
    if (noIFlag.ok) {
      expect(noIFlag.bytes[0]).toBe(0x00);
      expect(noIFlag.warnings.some((w) => w.fieldId === 'flags' && w.message.includes('I-flag'))).toBe(
        true,
      );
    }

    // 2. Non-zero reserved flag bits (with I=1 still set)
    const extraFlagBits = encodeVXLAN(makeVXLAN({ flags: manualValue(0x88) }), {
      layerIndex: 3,
      udp: validVxlanUdp,
    });
    expect(extraFlagBits.ok).toBe(true);
    if (extraFlagBits.ok) {
      expect(extraFlagBits.bytes[0]).toBe(0x88);
      expect(
        extraFlagBits.warnings.some(
          (w) => w.fieldId === 'flags' && w.message.includes('reserved bit'),
        ),
      ).toBe(true);
    }

    // 3. Non-zero reserved1 (24b) and reserved2 (8b)
    const nonZeroRes = encodeVXLAN(makeVXLAN({ reserved1: 0x010203, reserved2: 0xab }), {
      layerIndex: 3,
      udp: validVxlanUdp,
    });
    expect(nonZeroRes.ok).toBe(true);
    if (nonZeroRes.ok) {
      expect(nonZeroRes.bytes).toEqual(
        new Uint8Array([0x08, 0x01, 0x02, 0x03, 0x00, 0x00, 0x64, 0xab]),
      );
      expect(nonZeroRes.warnings.map((w) => w.fieldId)).toEqual(['reserved1', 'reserved2']);
    }

    // 4. Immediately preceding layer is not UDP
    const noUdp = encodeVXLAN(makeVXLAN(), {
      layerIndex: 1,
      udp: { status: 'absent' },
    });
    expect(noUdp.ok).toBe(true);
    if (noUdp.ok) {
      expect(noUdp.warnings.some((w) => w.message.includes('No underlying UDP layer'))).toBe(true);
    }

    // 5. Preceding UDP destination port is not 4789
    const wrongPort = encodeVXLAN(makeVXLAN(), {
      layerIndex: 3,
      udp: { status: 'valid', srcPort: 49152, dstPort: 8472 },
    });
    expect(wrongPort.ok).toBe(true);
    if (wrongPort.ok) {
      expect(
        wrongPort.warnings.some((w) => w.message.includes('8472') && w.message.includes('4789')),
      ).toBe(true);
    }
  });

  it('rejects out-of-range flags, reserved1, and reserved2 values with field-scoped errors', () => {
    const invalid = encodeVXLAN(
      makeVXLAN({
        flags: manualValue(0x100),
        reserved1: 0x1_0000_00,
        reserved2: 256,
      }),
      { layerIndex: 3, udp: validVxlanUdp },
    );
    expect(invalid.ok).toBe(false);
    if (!invalid.ok) {
      expect(invalid.errors.map((e) => e.fieldId)).toEqual(['flags', 'reserved1', 'reserved2']);
    }
  });
});
