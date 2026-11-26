import { describe, expect, it } from 'vitest';
import { FIELD_DOCS, getFieldDoc, normalizeFieldDocId } from './fieldDocs';
import { autoValue, type Layer, type LayerType } from './layers/types';
import { buildPacket } from './packet';
import {
  createDefaultARP,
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultGRE,
  createDefaultICMP,
  createDefaultICMPv6,
  createDefaultIPv4,
  createDefaultIPv6,
  createDefaultTCP,
  createDefaultUDP,
  createDefaultVLAN,
  createDefaultVXLAN,
  createPresets,
} from './presets';

const SPECIFIC_SECTION_PATTERN = /(§\d+(?:\.\d+)*|"[^"]+")/;

describe('FIELD_DOCS coverage and quality', () => {
  it('covers 100% of emitted layer FieldSpan.fieldIds across all presets and variants with zero orphaned keys', () => {
    const emittedByLayer = new Map<LayerType, Set<string>>();

    const collectSpans = (layers: readonly Layer[], payload: Uint8Array = new Uint8Array(0)) => {
      const built = buildPacket(layers, payload);
      expect(built.ok).toBe(true);
      if (!built.ok) return;

      for (const span of built.spans) {
        if (span.section !== 'layer' || span.layerType === 'payload') continue;
        let set = emittedByLayer.get(span.layerType);
        if (!set) {
          set = new Set<string>();
          emittedByLayer.set(span.layerType, set);
        }
        set.add(normalizeFieldDocId(span.fieldId));

        const doc = getFieldDoc(span.layerType, span.fieldId);
        expect(
          doc,
          `Missing FIELD_DOCS entry for ${span.layerType}.${span.fieldId}`,
        ).toBeDefined();
      }
    };

    // 1) Every built-in preset
    for (const preset of createPresets()) {
      collectSpans(preset.layers, preset.payloadBytes);
    }

    // 2) All layer types and variants:
    //    - VLAN tag
    //    - IPv4 with all flag bits toggled
    //    - IPv6 fixed header
    //    - ICMPv6 Echo and Raw (Packet Too Big) variants
    //    - GRE with all optional fields enabled (C=1, K=1, S=1)
    //    - TCP with all 8 control bits toggled and every TCP option kind + padding
    //    - BGP OPEN (1), UPDATE (2), NOTIFICATION (3), and KEEPALIVE (4)
    collectSpans([
      createDefaultEthernet(),
      createDefaultVLAN(),
      createDefaultARP(),
      {
        ...createDefaultIPv4(),
        flags: { reserved: true, df: true, mf: true },
        options: [
          { kind: 'routerAlert', value: 0 },
          { kind: 'rr', pointer: autoValue(), addresses: ['192.0.2.1'] },
          { kind: 'timestamp', pointer: 5, overflow: 0, flag: 0, dataHex: '00 00 00 01' },
          { kind: 'nop' },
          { kind: 'raw', optionType: 134, length: autoValue(), dataHex: 'aa bb' },
          { kind: 'eol' },
        ],
      },
      {
        ...createDefaultIPv4(),
        options: [
          { kind: 'lsrr', pointer: autoValue(), addresses: ['192.0.2.1'] },
          { kind: 'ssrr', pointer: autoValue(), addresses: ['192.0.2.2'] },
        ],
      },
      createDefaultIPv6(),
      createDefaultICMP(),
      createDefaultICMPv6(),
      {
        ...createDefaultICMPv6(),
        icmpType: 2,
        rest: { kind: 'raw', value: 1280 },
      },
      {
        ...createDefaultGRE(),
        checksumPresent: true,
        keyPresent: true,
        sequencePresent: true,
        key: 0x11223344,
        sequenceNumber: 1,
      },
      createDefaultUDP(),
      {
        ...createDefaultTCP(),
        flags: {
          cwr: true,
          ece: true,
          urg: true,
          ack: true,
          psh: true,
          rst: true,
          syn: true,
          fin: true,
        },
        options: [
          { kind: 'mss', mss: 1460 },
          { kind: 'windowScale', shiftCount: 7 },
          { kind: 'sackPermitted' },
          { kind: 'timestamps', tsVal: 123, tsEcr: 456 },
          { kind: 'nop' },
          { kind: 'raw', optionKind: 30, length: autoValue(), dataHex: 'aa bb' },
          { kind: 'eol' },
        ],
      },
      {
        ...createDefaultTCP(),
        options: [
          {
            kind: 'sack',
            blocks: [
              { left: 100, right: 200 },
              { left: 300, right: 400 },
            ],
          },
        ],
      },
      createDefaultVXLAN(),
      { ...createDefaultBGP(), bgpType: 1 },
      { ...createDefaultBGP(), bgpType: 2 },
      { ...createDefaultBGP(), bgpType: 3 },
      { ...createDefaultBGP(), bgpType: 4 },
    ]);

    // 3) Assert no LayerType is missing and no FIELD_DOCS key is orphaned
    const documentedLayerTypes = Object.keys(FIELD_DOCS) as LayerType[];
    expect(new Set(documentedLayerTypes)).toEqual(new Set(emittedByLayer.keys()));

    for (const layerType of documentedLayerTypes) {
      const documentedKeys = Object.keys(FIELD_DOCS[layerType]);
      const emittedKeys = emittedByLayer.get(layerType) ?? new Set<string>();

      for (const key of documentedKeys) {
        expect(
          emittedKeys.has(key),
          `Orphaned FIELD_DOCS key: ${layerType}.${key} is never emitted by any encoder`,
        ).toBe(true);
      }
    }
  });

  it('gives every field a non-empty summary and a specific RFC/IEEE section reference', () => {
    for (const [layerType, fields] of Object.entries(FIELD_DOCS)) {
      for (const [fieldId, doc] of Object.entries(fields)) {
        expect(
          doc.summary.trim().length,
          `Empty summary for ${layerType}.${fieldId}`,
        ).toBeGreaterThan(10);
        expect(
          doc.reference,
          `Reference for ${layerType}.${fieldId} must name a specific section, not just a document number`,
        ).toMatch(SPECIFIC_SECTION_PATTERN);
      }
    }
  });

  it('returns undefined for unknown fieldIds and prototype keys', () => {
    expect(getFieldDoc('ipv4', 'nonExistentField')).toBeUndefined();
    expect(getFieldDoc('ipv4', 'toString')).toBeUndefined();
    expect(getFieldDoc('ipv4', 'constructor')).toBeUndefined();
    expect(getFieldDoc('ipv4', '__proto__')).toBeUndefined();
  });
});
