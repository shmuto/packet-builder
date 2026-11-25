import { describe, expect, it } from 'vitest';
import { ARP_OP_REPLY, ARP_OP_REQUEST, encodeARP } from './arp';
import { autoValue, manualValue, type ARPLayer } from './types';

function makeBaseARP(overrides: Partial<ARPLayer> = {}): ARPLayer {
  return {
    type: 'arp',
    hardwareType: autoValue(),
    protocolType: autoValue(),
    hardwareLength: autoValue(),
    protocolLength: autoValue(),
    operation: ARP_OP_REQUEST,
    senderMac: '66:77:88:99:aa:bb',
    senderIp: '192.168.0.1',
    targetMac: '00:00:00:00:00:00',
    targetIp: '192.168.0.2',
    ...overrides,
  };
}

describe('encodeARP', () => {
  it('encodes a standard 28-byte ARP Request per RFC 826', () => {
    const result = encodeARP(makeBaseARP(), { layerIndex: 0 });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(
      new Uint8Array([
        0x00, 0x01, // HTYPE = 1 (Ethernet)
        0x08, 0x00, // PTYPE = 0x0800 (IPv4)
        0x06, // HLEN = 6
        0x04, // PLEN = 4
        0x00, 0x01, // OPER = 1 (Request)
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // SHA
        0xc0, 0xa8, 0x00, 0x01, // SPA (192.168.0.1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // THA
        0xc0, 0xa8, 0x00, 0x02, // TPA (192.168.0.2)
      ]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({
      hardwareType: 1,
      protocolType: 0x0800,
      hardwareLength: 6,
      protocolLength: 4,
    });
  });

  it('accepts ARP Reply (operation=2) without warnings and warns on non-1/2 operations', () => {
    const reply = encodeARP(
      makeBaseARP({ operation: ARP_OP_REPLY, targetMac: '00:11:22:33:44:55' }),
      { layerIndex: 0 },
    );
    expect(reply.ok).toBe(true);
    if (reply.ok) {
      expect(reply.bytes.slice(6, 8)).toEqual(new Uint8Array([0x00, 0x02]));
      expect(reply.warnings).toHaveLength(0);
    }

    const rarp = encodeARP(makeBaseARP({ operation: 3 }), { layerIndex: 0 });
    expect(rarp.ok).toBe(true);
    if (rarp.ok) {
      expect(rarp.warnings.some((w) => w.fieldId === 'operation')).toBe(true);
    }
  });

  it('applies manual overrides for HTYPE / PTYPE / HLEN / PLEN and warns on non-standard values', () => {
    const result = encodeARP(
      makeBaseARP({
        hardwareType: manualValue(6),
        protocolType: manualValue(0x86dd),
        hardwareLength: manualValue(8),
        protocolLength: manualValue(16),
      }),
      { layerIndex: 0 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(0, 6)).toEqual(new Uint8Array([0x00, 0x06, 0x86, 0xdd, 0x08, 0x10]));
    expect(result.warnings.map((w) => w.fieldId)).toEqual([
      'hardwareType',
      'protocolType',
      'hardwareLength',
      'protocolLength',
    ]);
  });

  it('collects validation errors for out-of-range fields and malformed addresses', () => {
    const result = encodeARP(
      makeBaseARP({
        hardwareType: manualValue(0x10000),
        protocolType: manualValue(-1),
        hardwareLength: manualValue(256),
        protocolLength: manualValue(-1),
        operation: 70000,
        senderMac: 'bad',
        senderIp: '999.0.0.1',
        targetMac: 'zz:00:00:00:00:00',
        targetIp: '',
      }),
      { layerIndex: 0 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual([
      'hardwareType',
      'protocolType',
      'hardwareLength',
      'protocolLength',
      'operation',
      'senderMac',
      'senderIp',
      'targetMac',
      'targetIp',
    ]);
  });

  it('accepts minimum (0) and maximum (0xff / 0xffff) boundary values', () => {
    const minResult = encodeARP(
      makeBaseARP({
        hardwareType: manualValue(0),
        protocolType: manualValue(0),
        hardwareLength: manualValue(0),
        protocolLength: manualValue(0),
        operation: 0,
      }),
      { layerIndex: 0 },
    );
    expect(minResult.ok).toBe(true);
    if (minResult.ok) {
      expect(minResult.bytes.slice(0, 8)).toEqual(new Uint8Array(8));
    }

    const maxResult = encodeARP(
      makeBaseARP({
        hardwareType: manualValue(0xffff),
        protocolType: manualValue(0xffff),
        hardwareLength: manualValue(0xff),
        protocolLength: manualValue(0xff),
        operation: 0xffff,
      }),
      { layerIndex: 0 },
    );
    expect(maxResult.ok).toBe(true);
    if (maxResult.ok) {
      expect(maxResult.bytes.slice(0, 8)).toEqual(
        new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
      );
    }
  });
});
