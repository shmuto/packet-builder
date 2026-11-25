import { describe, expect, it } from 'vitest';
import {
  BGP_DEFAULT_MARKER_HEX,
  BGP_TYPE_KEEPALIVE,
  BGP_TYPE_NOTIFICATION,
  BGP_TYPE_OPEN,
  BGP_TYPE_UPDATE,
  encodeBGP,
} from './bgp';
import { autoValue, manualValue, type BGPLayer } from './types';

function makeBaseBGP(overrides: Partial<BGPLayer> = {}): BGPLayer {
  return {
    type: 'bgp',
    bgpType: BGP_TYPE_OPEN,
    marker: autoValue(),
    length: autoValue(),
    version: autoValue(),
    myAs: 65001,
    holdTime: 180,
    bgpIdentifier: '192.168.0.1',
    optParamLength: autoValue(),
    withdrawnRoutesLength: autoValue(),
    totalPathAttrLength: autoValue(),
    errorCode: 6,
    errorSubcode: 4,
    ...overrides,
  };
}

describe('encodeBGP', () => {
  const bgpTcpPorts = { srcPort: 54321, dstPort: 179 };

  it('encodes a 29-byte BGP-4 OPEN message per RFC 4271 §4.2', () => {
    const result = encodeBGP(makeBaseBGP(), {
      layerIndex: 0,
      upperBytesLength: 0,
      tcpPorts: bgpTcpPorts,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(
      new Uint8Array([
        // 16-byte all-ones Marker
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        // Length = 29 (0x001d), Type = 1 (OPEN)
        0x00, 0x1d, 0x01,
        // Version = 4, My AS = 65001 (0xfde9), Hold Time = 180 (0x00b4)
        0x04, 0xfd, 0xe9, 0x00, 0xb4,
        // BGP Identifier = 192.168.0.1, Opt Parm Len = 0
        0xc0, 0xa8, 0x00, 0x01, 0x00,
      ]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({
      length: 29,
      version: 4,
      optParamLength: 0,
    });
  });

  it('encodes KEEPALIVE (19B), NOTIFICATION (21B), and UPDATE (23B) messages per RFC 4271', () => {
    // KEEPALIVE (19B)
    const keepalive = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_KEEPALIVE }), {
      layerIndex: 0,
      upperBytesLength: 0,
      tcpPorts: bgpTcpPorts,
    });
    expect(keepalive.ok).toBe(true);
    if (keepalive.ok) {
      expect(keepalive.bytes.length).toBe(19);
      expect(keepalive.bytes.slice(16, 19)).toEqual(new Uint8Array([0x00, 0x13, 0x04]));
      expect(keepalive.warnings).toHaveLength(0);
    }

    // NOTIFICATION (21B: Error Code=6 Cease, Subcode=4 Administrative Reset)
    const notif = encodeBGP(
      makeBaseBGP({ bgpType: BGP_TYPE_NOTIFICATION, errorCode: 6, errorSubcode: 4 }),
      { layerIndex: 0, upperBytesLength: 0, tcpPorts: bgpTcpPorts },
    );
    expect(notif.ok).toBe(true);
    if (notif.ok) {
      expect(notif.bytes.length).toBe(21);
      expect(notif.bytes.slice(16, 21)).toEqual(new Uint8Array([0x00, 0x15, 0x03, 0x06, 0x04]));
      expect(notif.warnings).toHaveLength(0);
    }

    // UPDATE (23B End-of-RIB marker: Withdrawn=0, TotalPathAttr=0)
    const update = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_UPDATE }), {
      layerIndex: 0,
      upperBytesLength: 0,
      tcpPorts: bgpTcpPorts,
    });
    expect(update.ok).toBe(true);
    if (update.ok) {
      expect(update.bytes.length).toBe(23);
      expect(update.bytes.slice(16, 23)).toEqual(
        new Uint8Array([0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00]),
      );
      expect(update.warnings).toHaveLength(0);
    }
  });

  it('enforces RFC 4271 Hold Time boundary (0 and >=3 valid; 1 and 2 warn)', () => {
    for (const validHold of [0, 3, 180, 65535]) {
      const res = encodeBGP(makeBaseBGP({ holdTime: validHold }), {
        layerIndex: 0,
        upperBytesLength: 0,
        tcpPorts: bgpTcpPorts,
      });
      expect(res.ok && res.warnings).toEqual([]);
    }

    for (const badHold of [1, 2]) {
      const res = encodeBGP(makeBaseBGP({ holdTime: badHold }), {
        layerIndex: 0,
        upperBytesLength: 0,
        tcpPorts: bgpTcpPorts,
      });
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.warnings.some((w) => w.fieldId === 'holdTime')).toBe(true);
      }
    }
  });

  it('warns on KEEPALIVE payload, non-179 TCP ports, non-all-ff marker, and length > 4096', () => {
    const kaPayload = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_KEEPALIVE }), {
      layerIndex: 0,
      upperBytesLength: 4,
      tcpPorts: { srcPort: 1000, dstPort: 80 },
    });
    expect(kaPayload.ok).toBe(true);
    if (kaPayload.ok) {
      expect(kaPayload.warnings.some((w) => w.message.includes('179'))).toBe(true);
      expect(kaPayload.warnings.some((w) => w.message.includes('KEEPALIVE'))).toBe(true);
    }

    const customMarker = encodeBGP(
      makeBaseBGP({ marker: manualValue('00'.repeat(16)) }),
      { layerIndex: 0, upperBytesLength: 0, tcpPorts: bgpTcpPorts },
    );
    expect(customMarker.ok).toBe(true);
    if (customMarker.ok) {
      expect(customMarker.bytes.slice(0, 16)).toEqual(new Uint8Array(16));
      expect(customMarker.warnings.some((w) => w.fieldId === 'marker')).toBe(true);
    }

    // 4096 exact = no length warning; 4097 = RFC 4271 §4.1 warning; 65536 = error
    const exact4096 = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_UPDATE }), {
      layerIndex: 0,
      upperBytesLength: 4096 - 23,
      tcpPorts: bgpTcpPorts,
    });
    expect(exact4096.ok && exact4096.warnings).toEqual([]);

    const over4096 = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_UPDATE }), {
      layerIndex: 0,
      upperBytesLength: 4097 - 23,
      tcpPorts: bgpTcpPorts,
    });
    expect(over4096.ok).toBe(true);
    if (over4096.ok) {
      expect(over4096.warnings.some((w) => w.fieldId === 'length')).toBe(true);
    }

    const over65535 = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_UPDATE }), {
      layerIndex: 0,
      upperBytesLength: 65536 - 23,
      tcpPorts: bgpTcpPorts,
    });
    expect(over65535.ok).toBe(false);
  });

  it('rejects OPEN OptParmLen > 255, wrong-length Marker, and invalid BGP Identifier', () => {
    // Exact boundary: 255 bytes of OPEN optional parameters is valid
    const optExact255 = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_OPEN }), {
      layerIndex: 0,
      upperBytesLength: 255,
      tcpPorts: bgpTcpPorts,
    });
    expect(optExact255.ok && optExact255.warnings).toEqual([]);
    if (optExact255.ok) {
      expect(optExact255.bytes[28]).toBe(255);
    }

    const optOverflow = encodeBGP(makeBaseBGP({ bgpType: BGP_TYPE_OPEN }), {
      layerIndex: 0,
      upperBytesLength: 256,
      tcpPorts: bgpTcpPorts,
    });
    expect(optOverflow.ok).toBe(false);
    if (!optOverflow.ok) {
      expect(optOverflow.errors.some((e) => e.fieldId === 'optParamLength')).toBe(true);
    }

    const badFields = encodeBGP(
      makeBaseBGP({
        marker: manualValue('ffff'), // only 2 bytes
        myAs: 70000,
        bgpIdentifier: 'invalid-ip',
      }),
      { layerIndex: 0, upperBytesLength: 0, tcpPorts: bgpTcpPorts },
    );
    expect(badFields.ok).toBe(false);
    if (!badFields.ok) {
      expect(badFields.errors.map((e) => e.fieldId)).toEqual(['marker', 'myAs', 'bgpIdentifier']);
    }

    // Valid all-ff manual marker produces zero warnings
    const validManualMarker = encodeBGP(
      makeBaseBGP({ marker: manualValue(BGP_DEFAULT_MARKER_HEX) }),
      { layerIndex: 0, upperBytesLength: 0, tcpPorts: bgpTcpPorts },
    );
    expect(validManualMarker.ok && validManualMarker.warnings).toEqual([]);

    // Manual Length < 19 warns per RFC 4271 §4.1
    const shortLen = encodeBGP(makeBaseBGP({ length: manualValue(18) }), {
      layerIndex: 0,
      upperBytesLength: 0,
      tcpPorts: bgpTcpPorts,
    });
    expect(shortLen.ok).toBe(true);
    if (shortLen.ok) {
      expect(shortLen.warnings.some((w) => w.fieldId === 'length')).toBe(true);
    }

    // UPDATE with non-zero manual Withdrawn Routes Length warns about RFC 4271 §4.3 layout
    const withdrawnWarn = encodeBGP(
      makeBaseBGP({
        bgpType: BGP_TYPE_UPDATE,
        withdrawnRoutesLength: manualValue(4),
      }),
      { layerIndex: 0, upperBytesLength: 4, tcpPorts: bgpTcpPorts },
    );
    expect(withdrawnWarn.ok).toBe(true);
    if (withdrawnWarn.ok) {
      expect(withdrawnWarn.warnings.some((w) => w.fieldId === 'withdrawnRoutesLength')).toBe(true);
    }
  });
});
