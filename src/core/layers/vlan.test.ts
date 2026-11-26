import { describe, expect, it } from 'vitest';
import { autoValue, manualValue, type VLANLayer } from './types';
import { encodeVLAN, VLAN_FIELD_SPANS, VLAN_HEADER_LENGTH } from './vlan';

function makeBaseVLAN(overrides: Partial<VLANLayer> = {}): VLANLayer {
  return {
    type: 'vlan',
    pcp: 0,
    dei: false,
    vid: 100,
    etherType: autoValue(),
    ...overrides,
  };
}

describe('encodeVLAN', () => {
  it('encodes 4-byte TCI + EtherType and packs PCP(3b)/DEI(1b)/VID(12b) accurately', () => {
    // PCP=5 (101b), DEI=0 (0b), VID=100 (0x064) -> TCI = 0xa064
    const res = encodeVLAN(makeBaseVLAN({ pcp: 5, dei: false, vid: 100 }), {
      layerIndex: 1,
      upperLayerType: 'ipv4',
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.bytes).toEqual(new Uint8Array([0xa0, 0x64, 0x08, 0x00]));
    expect(res.warnings).toHaveLength(0);
    expect(res.resolvedAutoValues).toEqual({ etherType: 0x0800 });

    // PCP=7 (111b), DEI=1 (1b), VID=4094 (0xffe) -> TCI = 0xfffe
    const maxFields = encodeVLAN(makeBaseVLAN({ pcp: 7, dei: true, vid: 4094 }), {
      layerIndex: 1,
      upperLayerType: 'ipv6',
    });
    expect(maxFields.ok).toBe(true);
    if (!maxFields.ok) return;
    expect(maxFields.bytes).toEqual(new Uint8Array([0xff, 0xfe, 0x86, 0xdd]));
    expect(maxFields.warnings).toHaveLength(0);

    // VLAN_FIELD_SPANS must be contiguous across all 32 bits
    let cursor = 0;
    for (const span of VLAN_FIELD_SPANS) {
      expect(span.bitOffset).toBe(cursor);
      cursor += span.bitLength;
    }
    expect(cursor).toBe(VLAN_HEADER_LENGTH * 8);
  });

  it('auto-selects inner EtherType for IPv4 (0x0800), ARP (0x0806), IPv6 (0x86dd), and inner VLAN C-tag (0x8100)', () => {
    const ipv4 = encodeVLAN(makeBaseVLAN(), { layerIndex: 1, upperLayerType: 'ipv4' });
    const arp = encodeVLAN(makeBaseVLAN(), { layerIndex: 1, upperLayerType: 'arp' });
    const ipv6 = encodeVLAN(makeBaseVLAN(), { layerIndex: 1, upperLayerType: 'ipv6' });
    const innerVlan = encodeVLAN(makeBaseVLAN(), { layerIndex: 1, upperLayerType: 'vlan' });

    expect(ipv4.ok && ipv4.bytes.slice(2, 4)).toEqual(new Uint8Array([0x08, 0x00]));
    expect(arp.ok && arp.bytes.slice(2, 4)).toEqual(new Uint8Array([0x08, 0x06]));
    expect(ipv6.ok && ipv6.bytes.slice(2, 4)).toEqual(new Uint8Array([0x86, 0xdd]));
    expect(innerVlan.ok && innerVlan.bytes.slice(2, 4)).toEqual(new Uint8Array([0x81, 0x00]));
    expect(innerVlan.ok && innerVlan.warnings).toEqual([]);
  });

  it('warns on VID 0 (priority-tagged) and VID 4095 (reserved), does not warn on 1 or 4094, and errors on VID 4096 or PCP 8', () => {
    const vid0 = encodeVLAN(makeBaseVLAN({ vid: 0 }), { layerIndex: 1, upperLayerType: 'ipv4' });
    expect(vid0.ok).toBe(true);
    if (vid0.ok) {
      expect(vid0.warnings.some((w) => w.fieldId === 'vid' && w.message.includes('priority-tagged'))).toBe(true);
    }

    const vid1 = encodeVLAN(makeBaseVLAN({ vid: 1 }), { layerIndex: 1, upperLayerType: 'ipv4' });
    expect(vid1.ok && vid1.warnings).toEqual([]);

    const vid4094 = encodeVLAN(makeBaseVLAN({ vid: 4094 }), { layerIndex: 1, upperLayerType: 'ipv4' });
    expect(vid4094.ok && vid4094.warnings).toEqual([]);

    const vid4095 = encodeVLAN(makeBaseVLAN({ vid: 4095 }), { layerIndex: 1, upperLayerType: 'ipv4' });
    expect(vid4095.ok).toBe(true);
    if (vid4095.ok) {
      expect(vid4095.warnings.some((w) => w.fieldId === 'vid' && w.message.includes('reserved'))).toBe(true);
    }

    const vid4096 = encodeVLAN(makeBaseVLAN({ vid: 4096 }), { layerIndex: 1, upperLayerType: 'ipv4' });
    expect(vid4096.ok).toBe(false);
    if (!vid4096.ok) {
      expect(vid4096.errors.map((e) => e.fieldId)).toEqual(['vid']);
    }

    const pcp8 = encodeVLAN(makeBaseVLAN({ pcp: 8 }), { layerIndex: 1, upperLayerType: 'ipv4' });
    expect(pcp8.ok).toBe(false);
    if (!pcp8.ok) {
      expect(pcp8.errors.map((e) => e.fieldId)).toEqual(['pcp']);
    }
  });

  it('prefers manual inner EtherType and warns on mismatch or unknown upper layer', () => {
    const manualMismatch = encodeVLAN(makeBaseVLAN({ etherType: manualValue(0x88b5) }), {
      layerIndex: 1,
      upperLayerType: 'ipv4',
    });
    expect(manualMismatch.ok).toBe(true);
    if (manualMismatch.ok) {
      expect(manualMismatch.bytes.slice(2, 4)).toEqual(new Uint8Array([0x88, 0xb5]));
      expect(manualMismatch.warnings.some((w) => w.fieldId === 'etherType')).toBe(true);
    }

    const unknownUpper = encodeVLAN(makeBaseVLAN(), { layerIndex: 1, upperLayerType: null });
    expect(unknownUpper.ok).toBe(true);
    if (unknownUpper.ok) {
      expect(unknownUpper.bytes.slice(2, 4)).toEqual(new Uint8Array([0x08, 0x00]));
      expect(unknownUpper.warnings.some((w) => w.fieldId === 'etherType')).toBe(true);
    }
  });
});
