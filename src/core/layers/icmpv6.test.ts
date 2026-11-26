import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseIPv6 } from '../bytes';
import {
  encodeICMPv6,
  getICMPv6FieldSpans,
  getICMPv6RawFieldLabel,
  ICMPV6_HEADER_LENGTH,
  ICMPV6_TYPE_ECHO_REPLY,
  ICMPV6_TYPE_ECHO_REQUEST,
  ICMPV6_TYPE_PACKET_TOO_BIG,
  ICMPV6_TYPE_PARAMETER_PROBLEM,
} from './icmpv6';
import { autoValue, manualValue, type ICMPv6Layer } from './types';

function mustIPv6(addr: string): Uint8Array {
  const res = parseIPv6(addr);
  if (!res.ok) throw new Error(res.error);
  return res.value;
}

function makeEchoLayer(overrides: Partial<ICMPv6Layer> = {}): ICMPv6Layer {
  return {
    type: 'icmpv6',
    icmpType: ICMPV6_TYPE_ECHO_REQUEST,
    code: 0,
    checksum: autoValue(),
    rest: { kind: 'echo', identifier: 1, sequence: 1 },
    ...overrides,
  };
}

describe('encodeICMPv6', () => {
  const ipv6Ctx = {
    status: 'valid' as const,
    version: 6 as const,
    srcIp: mustIPv6('2001:db8::1'),
    dstIp: mustIPv6('2001:db8::2'),
  };

  it('encodes Echo Request with IPv6 pseudo-header checksum and changes checksum when IPv6 src changes', () => {
    // Hand-verified RFC 4443 §2.3 / RFC 8200 §8.1 checksum:
    //   pseudo: 2001:db8::1 (0x2dba) + 2001:db8::2 (0x2dbb) + len 12 (0x000c) + NH 58 (0x003a) = 0x5bbb
    //   body: Type=128/Code=0 (0x8000) + ID=1 (0x0001) + Seq=1 (0x0001) + "ping" (0x7069+0x6e67=0xded0) = 0x15ed2
    //   sum = 0x1ba8d -> fold: 0xba8d + 1 = 0xba8e -> ~0xba8e = 0x4571
    const res1 = encodeICMPv6(makeEchoLayer(), {
      layerIndex: 1,
      upperBytes: encodeUtf8('ping'),
      ip: ipv6Ctx,
    });

    expect(res1.ok).toBe(true);
    if (!res1.ok) return;
    expect(res1.bytes).toEqual(new Uint8Array([0x80, 0x00, 0x45, 0x71, 0x00, 0x01, 0x00, 0x01]));
    expect(res1.warnings).toHaveLength(0);
    expect(res1.resolvedAutoValues).toEqual({ checksum: 0x4571 });

    // Changing ONLY IPv6 source address (::1 -> ::9, +8) changes checksum by -8 (0x4571 -> 0x4569)
    const res2 = encodeICMPv6(makeEchoLayer(), {
      layerIndex: 1,
      upperBytes: encodeUtf8('ping'),
      ip: {
        ...ipv6Ctx,
        srcIp: mustIPv6('2001:db8::9'),
      },
    });
    expect(res2.ok).toBe(true);
    if (!res2.ok) return;
    expect(res2.bytes.slice(2, 4)).toEqual(new Uint8Array([0x45, 0x69]));
    expect(res2.resolvedAutoValues.checksum).not.toBe(res1.resolvedAutoValues.checksum);
  });

  it('encodes raw 32-bit variants with RFC 4443 labels (MTU for Type 2, Pointer for Type 4, Unused otherwise)', () => {
    expect(getICMPv6RawFieldLabel(ICMPV6_TYPE_PACKET_TOO_BIG)).toBe('MTU');
    expect(getICMPv6RawFieldLabel(ICMPV6_TYPE_PARAMETER_PROBLEM)).toBe('Pointer');
    expect(getICMPv6RawFieldLabel(1)).toBe('Unused');
    expect(getICMPv6RawFieldLabel(3)).toBe('Unused');
    expect(getICMPv6RawFieldLabel(135)).toBe('Unused');

    const ptb: ICMPv6Layer = {
      type: 'icmpv6',
      icmpType: ICMPV6_TYPE_PACKET_TOO_BIG,
      code: 0,
      checksum: autoValue(),
      rest: { kind: 'raw', value: 1280 },
    };
    const res = encodeICMPv6(ptb, {
      layerIndex: 1,
      upperBytes: new Uint8Array(0),
      ip: ipv6Ctx,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.bytes[0]).toBe(2);
    expect(res.bytes[1]).toBe(0);
    expect(res.bytes.slice(4, 8)).toEqual(new Uint8Array([0x00, 0x00, 0x05, 0x00]));
    expect(res.spans.find((s) => s.fieldId === 'restValue')?.label).toBe('MTU');

    // Contiguous 64-bit spans for both Echo and Raw variants
    for (const variant of [makeEchoLayer(), ptb]) {
      const spans = getICMPv6FieldSpans(variant);
      let cursor = 0;
      for (const s of spans) {
        expect(s.bitOffset).toBe(cursor);
        cursor += s.bitLength;
      }
      expect(cursor).toBe(ICMPV6_HEADER_LENGTH * 8);
    }
  });

  it('accepts Type/Code boundaries 0 and 255 and rejects out-of-range values', () => {
    const minOk = encodeICMPv6(
      {
        type: 'icmpv6',
        icmpType: 0,
        code: 0,
        checksum: autoValue(),
        rest: { kind: 'raw', value: 0 },
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: ipv6Ctx },
    );
    expect(minOk.ok).toBe(true);

    const maxOk = encodeICMPv6(
      {
        type: 'icmpv6',
        icmpType: 255,
        code: 255,
        checksum: autoValue(),
        rest: { kind: 'raw', value: 0xffffffff },
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: ipv6Ctx },
    );
    expect(maxOk.ok).toBe(true);
    if (maxOk.ok) {
      expect(maxOk.bytes[0]).toBe(255);
      expect(maxOk.bytes[1]).toBe(255);
      expect(maxOk.bytes.slice(4, 8)).toEqual(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
    }

    const badEcho = encodeICMPv6(
      makeEchoLayer({
        icmpType: 256,
        code: -1,
        checksum: manualValue(0x10000),
        rest: { kind: 'echo', identifier: -1, sequence: 65536 },
      }),
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: ipv6Ctx },
    );
    expect(badEcho.ok).toBe(false);
    if (!badEcho.ok) {
      expect(badEcho.errors.map((e) => e.fieldId)).toEqual([
        'icmpType',
        'code',
        'identifier',
        'sequence',
        'checksum',
      ]);
    }

    const badRaw = encodeICMPv6(
      {
        type: 'icmpv6',
        icmpType: ICMPV6_TYPE_PACKET_TOO_BIG,
        code: 0,
        checksum: autoValue(),
        rest: { kind: 'raw', value: 0x100000000 },
      },
      { layerIndex: 0, upperBytes: new Uint8Array(0), ip: ipv6Ctx },
    );
    expect(badRaw.ok).toBe(false);
    if (!badRaw.ok) {
      expect(badRaw.errors.map((e) => e.fieldId)).toEqual(['restValue']);
    }
  });

  it('warns and writes 0x0000 when preceding layer is absent or IPv4 ("use ICMP")', () => {
    const absent = encodeICMPv6(makeEchoLayer(), {
      layerIndex: 0,
      upperBytes: new Uint8Array(0),
      ip: { status: 'absent' },
    });
    expect(absent.ok).toBe(true);
    if (absent.ok) {
      expect(absent.bytes.slice(2, 4)).toEqual(new Uint8Array([0x00, 0x00]));
      expect(absent.warnings.some((w) => w.fieldId === 'checksum')).toBe(true);
    }

    const overIPv4 = encodeICMPv6(makeEchoLayer(), {
      layerIndex: 1,
      upperBytes: new Uint8Array(0),
      ip: {
        status: 'valid',
        version: 4,
        srcIp: new Uint8Array([192, 168, 0, 1]),
        dstIp: new Uint8Array([192, 168, 0, 2]),
      },
    });
    expect(overIPv4.ok).toBe(true);
    if (overIPv4.ok) {
      expect(overIPv4.bytes.slice(2, 4)).toEqual(new Uint8Array([0x00, 0x00]));
      expect(overIPv4.warnings.some((w) => w.message.includes('use ICMP'))).toBe(true);
      expect(overIPv4.warnings.some((w) => w.fieldId === 'checksum')).toBe(true);
    }
  });

  it('prefers manual checksum and emits mismatch warning', () => {
    const res = encodeICMPv6(
      makeEchoLayer({ icmpType: ICMPV6_TYPE_ECHO_REPLY, checksum: manualValue(0xdead) }),
      {
        layerIndex: 1,
        upperBytes: encodeUtf8('ping'),
        ip: ipv6Ctx,
      },
    );
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.bytes.slice(2, 4)).toEqual(new Uint8Array([0xde, 0xad]));
    expect(res.warnings.some((w) => w.fieldId === 'checksum' && w.message.includes('0xdead'))).toBe(
      true,
    );
  });
});
