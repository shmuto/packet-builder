import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { encodeUtf8, readUint16BE, writeUint16BE } from '../bytes';
import { decodePacket } from '../decode';
import { getFieldDocFromRegistry } from '../fieldDocs';
import { buildPacket } from '../packet';
import { decodePermalink, encodePermalink } from '../permalink';
import { ok } from '../result';
import type { BaseLayer, LayerDefinition } from './definition';
import { createDefaultEthernet } from './ethernet';
import {
  expectNumber,
  validateAutoOrManualNumber,
  validateExactKeys,
} from './permalinkHelpers';
import {
  createLayerRegistry,
  getDefaultLayerRegistry,
  getLayerDefinitions,
} from './registry';
import {
  autoValue,
  manualValue,
  validateUintRange,
  type AutoOrManual,
  type Layer,
} from './types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CORE_DIR = path.resolve(__dirname, '..');

interface DummyLayer extends BaseLayer {
  readonly type: 'dummy';
  readonly tag: number;
  readonly version: AutoOrManual<number>;
}

const DUMMY_ETHERTYPE = 0x88b5;
const DUMMY_DEFAULT_VERSION = 1;

const dummyDefinition: LayerDefinition<DummyLayer, 'dummy'> = {
  type: 'dummy',
  minHeaderLength: 4,
  createDefault: () => ({
    type: 'dummy',
    tag: 0x1234,
    version: autoValue(),
  }),
  headerLength: () => 4,
  encode(layer, ctx) {
    const tagErr = validateUintRange(layer.tag, 0xffff, 'Dummy Tag');
    if (tagErr) {
      return {
        ok: false,
        errors: [{ layerIndex: ctx.layerIndex, fieldId: 'tag', message: tagErr }],
        warnings: [],
      };
    }
    const version = layer.version.mode === 'manual' ? layer.version.value : DUMMY_DEFAULT_VERSION;
    const buf = new Uint8Array(4);
    writeUint16BE(buf, 0, layer.tag);
    writeUint16BE(buf, 2, version);
    return {
      ok: true,
      bytes: buf,
      spans: [
        { fieldId: 'tag', label: 'Tag', bitOffset: 0, bitLength: 16 },
        { fieldId: 'version', label: 'Version', bitOffset: 16, bitLength: 16 },
      ],
      warnings: [],
      resolvedAutoValues: { version: DUMMY_DEFAULT_VERSION },
    };
  },
  decode(bytes, offset) {
    if (bytes.length - offset < 4) {
      return null;
    }
    const tag = readUint16BE(bytes, offset);
    const ver = readUint16BE(bytes, offset + 2);
    const layer: DummyLayer = {
      type: 'dummy',
      tag,
      version: ver === DUMMY_DEFAULT_VERSION ? autoValue() : manualValue(ver),
    };
    return {
      layers: [layer],
      payload: bytes.slice(offset + 4),
    };
  },
  validatePermalink(raw, ctx) {
    const checked = validateExactKeys(raw, ['type', 'tag', 'version'], ctx);
    if (!checked.ok) return checked;
    const tag = expectNumber(checked.value, 'tag', ctx);
    if (!tag.ok) return tag;
    const version = validateAutoOrManualNumber(checked.value.version, `${ctx}.version`);
    if (!version.ok) return version;
    return ok({
      type: 'dummy',
      tag: tag.value,
      version: version.value,
    });
  },
  fieldDocs: {
    tag: {
      summary: '16-bit identifier for test-only extensibility verification.',
      reference: 'IEEE 802 §9.2 (Local Experimental EtherType 0x88b5)',
    },
    version: {
      summary: '16-bit dummy protocol version (default 1).',
      reference: 'IEEE 802 §9.2',
    },
  },
  protocols: {
    etherType: DUMMY_ETHERTYPE,
    etherTypeLabel: 'Dummy Experimental',
  },
};

describe('core layer registry', () => {
  it('registers all built-in protocols with consistent bidirectional next-protocol tables', () => {
    const registry = getDefaultLayerRegistry();
    expect(registry.types).toHaveLength(12);

    const { tables } = registry;
    // EtherType round-trip
    expect(tables.resolveEthernetEtherType('ipv4')?.value).toBe(0x0800);
    expect(tables.byEtherType.get(0x0800)?.type).toBe('ipv4');
    expect(tables.resolveEthernetEtherType('ipv6')?.value).toBe(0x86dd);
    expect(tables.byEtherType.get(0x86dd)?.type).toBe('ipv6');
    expect(tables.resolveEthernetEtherType('arp')?.value).toBe(0x0806);
    expect(tables.byEtherType.get(0x0806)?.type).toBe('arp');
    expect(tables.resolveEthernetEtherType('vlan')?.value).toBe(0x8100);
    expect(tables.resolveEthernetEtherType('vlan', 'vlan')?.value).toBe(0x88a8);
    expect(tables.byEtherType.get(0x8100)?.type).toBe('vlan');
    expect(tables.byEtherType.get(0x88a8)?.type).toBe('vlan');
    expect(tables.byEtherType.get(0x9100)?.type).toBe('vlan');

    // IP protocol / Next Header round-trip
    expect(tables.resolveIPv4Protocol('icmp')).toBe(1);
    expect(tables.byIPv4Protocol.get(1)?.type).toBe('icmp');
    expect(tables.resolveIPv6NextHeader('icmp')).toBeNull();
    expect(tables.resolveIPv6NextHeader('icmpv6')).toBe(58);
    expect(tables.byIPv6NextHeader.get(58)?.type).toBe('icmpv6');
    expect(tables.resolveIPv4Protocol('tcp')).toBe(6);
    expect(tables.byIPv4Protocol.get(6)?.type).toBe('tcp');
    expect(tables.resolveIPv4Protocol('udp')).toBe(17);
    expect(tables.byIPv4Protocol.get(17)?.type).toBe('udp');
    expect(tables.resolveIPv4Protocol('gre')).toBe(47);
    expect(tables.byIPv4Protocol.get(47)?.type).toBe('gre');

    // GRE & transport ports
    expect(tables.resolveGreProtocolType('ethernet')?.value).toBe(0x6558);
    expect(tables.byGreProtocolType.get(0x6558)?.type).toBe('ethernet');
    expect(tables.byUdpPort.get(4789)?.type).toBe('vxlan');
    expect(tables.byTcpPort.get(179)?.type).toBe('bgp');
  });

  it('extensibility proof: a test-only dummy layer encodes, decodes from Ethernet, round-trips via permalink, and exposes field docs with zero production edits', () => {
    type ExtendedLayer = Layer | DummyLayer;
    const customRegistry = createLayerRegistry<ExtendedLayer>([
      ...(getLayerDefinitions() as unknown as readonly LayerDefinition<ExtendedLayer>[]),
      dummyDefinition as unknown as LayerDefinition<ExtendedLayer>,
    ]);

    const eth = createDefaultEthernet();
    const dummy: DummyLayer = { type: 'dummy', tag: 0xabcd, version: manualValue(2) };
    const payload = encodeUtf8('hello-dummy');

    // 1. Encode: Ethernet auto-infers EtherType 0x88b5 from the dummy definition
    const built = buildPacket([eth, dummy], payload, customRegistry);
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.bytes.slice(12, 14)).toEqual(new Uint8Array([0x88, 0xb5]));
    expect(built.bytes.slice(14, 18)).toEqual(new Uint8Array([0xab, 0xcd, 0x00, 0x02]));
    expect(built.resolvedAutoValues[0].etherType).toBe(DUMMY_ETHERTYPE);

    // 2. Decode from Ethernet: dispatches 0x88b5 to dummyDefinition and keeps Ethernet EtherType auto
    const decoded = decodePacket(built.bytes, 'ethernet', customRegistry);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.layers).toEqual([eth, dummy]);
    expect(decoded.value.payload).toEqual(payload);
    expect(decoded.value.notes).toHaveLength(0);

    // 3. Permalink round-trip
    const fragment = encodePermalink<ExtendedLayer>({
      layers: [eth, dummy],
      payload: { mode: 'text', text: 'hello-dummy' },
    });
    const restored = decodePermalink(fragment, customRegistry);
    expect(restored.ok).toBe(true);
    if (!restored.ok) return;
    expect(restored.value.layers).toEqual([eth, dummy]);

    // Default registry rejects the unregistered dummy layer
    expect(decodePermalink(fragment).ok).toBe(false);

    // 4. Field docs
    const tagDoc = getFieldDocFromRegistry(customRegistry, 'dummy', 'tag');
    expect(tagDoc?.reference).toContain('0x88b5');
  });

  it('keeps packet.ts, decode.ts, and permalink.ts free of per-layer type dispatch and within line budgets', () => {
    const layerTypes = getDefaultLayerRegistry().types;
    const typePattern = layerTypes.join('|');
    const dispatchRegex = new RegExp(
      `(?:case\\s+['"](?:${typePattern})['"]|(?:===|!==)\\s*['"](?:${typePattern})['"]|['"](?:${typePattern})['"]\\s*(?:===|!==))`,
      'g',
    );

    for (const relFile of ['packet.ts', 'decode.ts', 'permalink.ts']) {
      const source = fs.readFileSync(path.join(CORE_DIR, relFile), 'utf8');
      const matches = source.match(dispatchRegex) ?? [];
      expect(matches, `Unexpected layer-type dispatch in src/core/${relFile}`).toEqual([]);
    }

    const decodeLines = fs.readFileSync(path.join(CORE_DIR, 'decode.ts'), 'utf8').split('\n').length;
    const permalinkLines = fs
      .readFileSync(path.join(CORE_DIR, 'permalink.ts'), 'utf8')
      .split('\n').length;
    expect(decodeLines).toBeLessThanOrEqual(400);
    expect(permalinkLines).toBeLessThanOrEqual(300);
  });

  it('prevents protocol modules from referencing other layer types directly by string literal', () => {
    const layerTypes = getDefaultLayerRegistry().types;

    for (const ownType of layerTypes) {
      const otherTypes = layerTypes.filter((t) => t !== ownType);
      const otherPattern = otherTypes.join('|');
      const crossRefRegex = new RegExp(
        `(?:case\\s+['"](?:${otherPattern})['"]|(?:===|!==)\\s*['"](?:${otherPattern})['"]|['"](?:${otherPattern})['"]\\s*(?:===|!==)|\\btype:\\s*['"](?:${otherPattern})['"])`,
        'g',
      );

      const protoDir = path.join(__dirname, ownType);
      const files = fs
        .readdirSync(protoDir)
        .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'));
      expect(files.length).toBeGreaterThanOrEqual(1);

      for (const file of files) {
        const source = fs.readFileSync(path.join(protoDir, file), 'utf8');
        const matches = source.match(crossRefRegex) ?? [];
        expect(
          matches,
          `Protocol module src/core/layers/${ownType}/${file} should not reference other layer types directly`,
        ).toEqual([]);
      }
    }
  });
});
