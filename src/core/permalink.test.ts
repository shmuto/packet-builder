import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseHexBytes } from './bytes';
import { autoValue, manualValue, type Layer } from './layers/types';
import { buildPacket } from './packet';
import {
  buildPermalinkUrl,
  decodePermalink,
  encodePermalink,
  hasOnlyFiniteNumbers,
  MAX_PERMALINK_LAYERS,
  MAX_PERMALINK_PAYLOAD_BYTES,
  PERMALINK_PREFIX,
  type PermalinkState,
} from './permalink';
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
  createPresets,
} from './presets';

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeRawJson(rawJson: string): string {
  return `${PERMALINK_PREFIX}${toBase64Url(encodeUtf8(rawJson))}`;
}

describe('permalink', () => {
  it('round-trips every built-in preset with identical state and packet bytes', () => {
    for (const preset of createPresets()) {
      const state: PermalinkState = {
        layers: preset.layers,
        payload: { mode: 'text', text: preset.payloadText },
      };

      const fragment = encodePermalink(state);
      expect(fragment.startsWith(PERMALINK_PREFIX)).toBe(true);

      const decoded = decodePermalink(fragment);
      expect(decoded.ok).toBe(true);
      if (!decoded.ok) continue;

      expect(decoded.value).toEqual(state);

      const builtOriginal = buildPacket(state.layers, encodeUtf8(preset.payloadText));
      const builtDecoded = buildPacket(
        decoded.value.layers,
        decoded.value.payload.mode === 'text'
          ? encodeUtf8(decoded.value.payload.text)
          : new Uint8Array(0),
      );
      expect(builtOriginal.ok).toBe(true);
      expect(builtDecoded.ok).toBe(true);
      if (builtOriginal.ok && builtDecoded.ok) {
        expect(Array.from(builtDecoded.bytes)).toEqual(Array.from(builtOriginal.bytes));
      }
    }
  });

  it('round-trips an arbitrary nested stack with manual overrides and corrupted checksum', () => {
    const outerEth = createDefaultEthernet();
    const outerIp = {
      ...createDefaultIPv4(),
      srcIp: '10.0.0.1',
      dstIp: '10.0.0.2',
      ttl: 128,
      headerChecksum: manualValue(0xdead),
      flags: { reserved: true, df: false, mf: true },
    };
    const outerUdp = {
      ...createDefaultUDP(),
      srcPort: 50000,
      dstPort: 4789,
      checksum: manualValue(0x0000),
    };
    const innerEth = {
      ...createDefaultEthernet(),
      dstMac: 'aa:bb:cc:dd:ee:ff',
      srcMac: '11:22:33:44:55:66',
      etherType: manualValue(0x0800),
    };
    const innerIp = {
      ...createDefaultIPv4(),
      srcIp: '172.16.0.1',
      dstIp: '172.16.0.2',
      protocol: manualValue(6),
    };
    const innerTcp = {
      ...createDefaultTCP(),
      srcPort: 49152,
      dstPort: 179,
      flags: {
        cwr: true,
        ece: false,
        urg: true,
        ack: true,
        psh: true,
        rst: false,
        syn: false,
        fin: false,
      },
      dataOffset: manualValue(5),
      checksum: manualValue(0xbeef),
    };
    const bgpUpdate = {
      ...createDefaultBGP(),
      bgpType: 2 as const,
      marker: manualValue('ff'.repeat(16)),
      length: manualValue(23),
      withdrawnRoutesLength: manualValue(0),
      totalPathAttrLength: manualValue(0),
    };

    const state: PermalinkState = {
      layers: [outerEth, outerIp, outerUdp, innerEth, innerIp, innerTcp, bgpUpdate],
      payload: { mode: 'hex', hex: 'de ad be ef 01 02' },
    };

    const fragment = encodePermalink(state);
    // Also verify leading '#' is accepted
    const decoded = decodePermalink(`#${fragment}`);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    expect(decoded.value).toEqual(state);

    const payloadBytes = parseHexBytes(state.payload.mode === 'hex' ? state.payload.hex : '');
    expect(payloadBytes.ok).toBe(true);
    if (!payloadBytes.ok) return;

    const originalBuilt = buildPacket(state.layers, payloadBytes.value);
    const decodedPayloadBytes = parseHexBytes(
      decoded.value.payload.mode === 'hex' ? decoded.value.payload.hex : '',
    );
    expect(decodedPayloadBytes.ok).toBe(true);
    if (!decodedPayloadBytes.ok) return;

    const decodedBuilt = buildPacket(decoded.value.layers, decodedPayloadBytes.value);
    expect(originalBuilt.ok).toBe(true);
    expect(decodedBuilt.ok).toBe(true);
    if (originalBuilt.ok && decodedBuilt.ok) {
      expect(Array.from(decodedBuilt.bytes)).toEqual(Array.from(originalBuilt.bytes));
    }
  });

  it('round-trips all 11 layer types including VLAN, ARP, IPv6, ICMP, ICMPv6 (Echo & Raw), and GRE', () => {
    const state: PermalinkState = {
      layers: [
        createDefaultEthernet(),
        { ...createDefaultVLAN(), pcp: 5, dei: true, vid: 200, etherType: manualValue(0x8100) },
        {
          ...createDefaultARP(),
          hardwareType: manualValue(1),
          protocolType: manualValue(0x0800),
          hardwareLength: manualValue(6),
          protocolLength: manualValue(4),
          operation: 2,
        },
        createDefaultIPv4(),
        {
          ...createDefaultGRE(),
          checksumPresent: true,
          keyPresent: true,
          sequencePresent: true,
          version: manualValue(0),
          protocolType: manualValue(0x86dd),
          checksum: manualValue(0x1234),
          key: 0x11223344,
          sequenceNumber: 77,
        },
        {
          ...createDefaultIPv6(),
          trafficClass: 0x2e,
          flowLabel: 0x12345,
          payloadLength: manualValue(20),
          nextHeader: manualValue(17),
        },
        {
          ...createDefaultICMP(),
          checksum: manualValue(0x1234),
        },
        createDefaultICMPv6(),
        {
          ...createDefaultICMPv6(),
          icmpType: 2,
          checksum: manualValue(0xbeef),
          rest: { kind: 'raw', value: 1280 },
        },
        createDefaultUDP(),
        createDefaultTCP(),
        createDefaultBGP(),
      ],
      payload: { mode: 'text', text: '' },
    };

    const decoded = decodePermalink(encodePermalink(state));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.value).toEqual(state);
    }
  });

  it('round-trips text and hex payloads including non-ASCII UTF-8, BOM, and empty payloads', () => {
    const cases: PermalinkState['payload'][] = [
      { mode: 'text', text: '' },
      { mode: 'text', text: 'Hello, パケット積み木! 🚀 café \uFEFF' },
      { mode: 'hex', hex: '' },
      { mode: 'hex', hex: '00 ff 0a 1b' },
      { mode: 'hex', hex: 'not-valid-hex!' },
    ];

    for (const payload of cases) {
      const state: PermalinkState = { layers: [], payload };
      const decoded = decodePermalink(encodePermalink(state));
      expect(decoded.ok).toBe(true);
      if (decoded.ok) {
        expect(decoded.value).toEqual(state);
      }
    }
  });

  it('validates shape only so broken packet values load as-is for normal buildPacket error UI', () => {
    const brokenState: PermalinkState = {
      layers: [
        {
          ...createDefaultEthernet(),
          dstMac: 'not-a-mac',
          srcMac: 'zz:zz:zz:zz:zz:zz',
          etherType: manualValue(999999),
        },
        {
          ...createDefaultIPv4(),
          ttl: 999,
          tos: -5,
          srcIp: '999.999.999.999',
          dstIp: 'bad-ip',
        },
        {
          ...createDefaultBGP(),
          marker: manualValue('zz'),
          myAs: 70000,
        },
      ],
      payload: { mode: 'hex', hex: 'abc' },
    };

    const decoded = decodePermalink(encodePermalink(brokenState));
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    expect(decoded.value).toEqual(brokenState);

    const built = buildPacket(decoded.value.layers, new Uint8Array(0));
    expect(built.ok).toBe(false);
    if (!built.ok) {
      expect(built.errors.length).toBeGreaterThanOrEqual(4);
    }
  });

  describe('malformed inputs return err without throwing', () => {
    it('rejects missing prefix, wrong prefix, and unknown schema versions', () => {
      for (const bad of ['', '#', 'abc', 'v1=e30', 'p0=e30', 'p2=e30', 'p99=e30', 'p1=']) {
        const res = decodePermalink(bad);
        expect(res.ok).toBe(false);
      }
    });

    it('rejects invalid base64url strings', () => {
      for (const bad of [
        'p1=a', // length % 4 === 1
        'p1=abc+def', // '+' not allowed in base64url
        'p1=abc/def', // '/' not allowed in base64url
        'p1=e30=', // '=' padding not allowed
        'p1=hello world', // whitespace not allowed
        'p1=!!!', // invalid chars
      ]) {
        const res = decodePermalink(bad);
        expect(res.ok).toBe(false);
      }
    });

    it('rejects invalid UTF-8 sequences', () => {
      const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
      const res = decodePermalink(`${PERMALINK_PREFIX}${toBase64Url(invalidUtf8)}`);
      expect(res.ok).toBe(false);
    });

    it('rejects invalid JSON', () => {
      const res = decodePermalink(encodeRawJson('{not valid json'));
      expect(res.ok).toBe(false);
    });

    it('rejects root shape mismatches', () => {
      const badRoots = [
        'null',
        '[]',
        '"hello"',
        '123',
        '{}',
        '{"layers":[]}',
        '{"payload":{"mode":"text","text":""}}',
        '{"layers":[],"payload":{"mode":"text","text":""},"extra":1}',
        '{"layers":"not-array","payload":{"mode":"text","text":""}}',
      ];
      for (const raw of badRoots) {
        const res = decodePermalink(encodeRawJson(raw));
        expect(res.ok).toBe(false);
      }
    });

    it('rejects unknown layer types, missing/extra keys, wrong primitive types, bad AutoOrManual, and non-boolean flags', () => {
      const validEth = createDefaultEthernet();
      const validIp = createDefaultIPv4();
      const validTcp = createDefaultTCP();
      const validBgp = createDefaultBGP();
      const emptyPayload = { mode: 'text', text: '' };

      const badPayloads: unknown[] = [
        // Unknown layer type
        { layers: [{ type: 'ipv6' }], payload: emptyPayload },
        // Non-object layer
        { layers: ['ethernet'], payload: emptyPayload },
        // Missing key
        { layers: [{ type: 'ethernet', dstMac: validEth.dstMac, srcMac: validEth.srcMac }], payload: emptyPayload },
        // Extra key
        { layers: [{ ...validEth, extra: true }], payload: emptyPayload },
        // Wrong primitive type
        { layers: [{ ...validEth, dstMac: 12345 }], payload: emptyPayload },
        { layers: [{ ...validIp, ttl: '64' }], payload: emptyPayload },
        { layers: [{ ...validIp, ttl: null }], payload: emptyPayload },
        // Invalid AutoOrManual
        { layers: [{ ...validEth, etherType: { mode: 'invalid' } }], payload: emptyPayload },
        { layers: [{ ...validEth, etherType: { mode: 'auto', value: 0x0800 } }], payload: emptyPayload },
        { layers: [{ ...validEth, etherType: { mode: 'manual' } }], payload: emptyPayload },
        { layers: [{ ...validEth, etherType: { mode: 'manual', value: '0x0800' } }], payload: emptyPayload },
        { layers: [{ ...validBgp, marker: { mode: 'manual', value: 123 } }], payload: emptyPayload },
        // Invalid BGP message type
        { layers: [{ ...validBgp, bgpType: 5 }], payload: emptyPayload },
        { layers: [{ ...validBgp, bgpType: '1' }], payload: emptyPayload },
        // Non-boolean flags & malformed flags object
        { layers: [{ ...validIp, flags: { reserved: 0, df: true, mf: false } }], payload: emptyPayload },
        { layers: [{ ...validIp, flags: { reserved: false, df: true } }], payload: emptyPayload },
        { layers: [{ ...validTcp, flags: { ...validTcp.flags, syn: 'true' } }], payload: emptyPayload },
        // Malformed payload object
        { layers: [], payload: { mode: 'binary', data: '00' } },
        { layers: [], payload: { mode: 'text', text: 123 } },
        { layers: [], payload: { mode: 'text', text: 'hi', hex: '6869' } },
        { layers: [], payload: { mode: 'hex', hex: null } },
      ];

      for (const candidate of badPayloads) {
        const res = decodePermalink(encodeRawJson(JSON.stringify(candidate)));
        expect(res.ok).toBe(false);
      }
    });

    it('enforces the 64-layer maximum boundary', () => {
      const eth = createDefaultEthernet();
      const maxValid: PermalinkState = {
        layers: Array.from({ length: MAX_PERMALINK_LAYERS }, () => eth),
        payload: { mode: 'text', text: '' },
      };
      expect(decodePermalink(encodePermalink(maxValid)).ok).toBe(true);

      const tooMany: PermalinkState = {
        layers: Array.from({ length: MAX_PERMALINK_LAYERS + 1 }, () => eth),
        payload: { mode: 'text', text: '' },
      };
      const res = decodePermalink(encodePermalink(tooMany));
      expect(res.ok).toBe(false);
    });

    it('enforces the 65535-byte decoded payload boundary for both text and hex modes', () => {
      // Text mode ASCII boundary
      const textExact: PermalinkState = {
        layers: [],
        payload: { mode: 'text', text: 'a'.repeat(MAX_PERMALINK_PAYLOAD_BYTES) },
      };
      expect(decodePermalink(encodePermalink(textExact)).ok).toBe(true);

      const textOver: PermalinkState = {
        layers: [],
        payload: { mode: 'text', text: 'a'.repeat(MAX_PERMALINK_PAYLOAD_BYTES + 1) },
      };
      expect(decodePermalink(encodePermalink(textOver)).ok).toBe(false);

      // Text mode multi-byte UTF-8 boundary (3 bytes per char: 21845 * 3 = 65535, 21846 * 3 = 65538)
      const utf8Exact: PermalinkState = {
        layers: [],
        payload: { mode: 'text', text: 'あ'.repeat(21845) },
      };
      expect(decodePermalink(encodePermalink(utf8Exact)).ok).toBe(true);

      const utf8Over: PermalinkState = {
        layers: [],
        payload: { mode: 'text', text: 'あ'.repeat(21846) },
      };
      expect(decodePermalink(encodePermalink(utf8Over)).ok).toBe(false);

      // Hex mode boundary
      const hexExact: PermalinkState = {
        layers: [],
        payload: { mode: 'hex', hex: 'ab'.repeat(MAX_PERMALINK_PAYLOAD_BYTES) },
      };
      expect(decodePermalink(encodePermalink(hexExact)).ok).toBe(true);

      const hexOver: PermalinkState = {
        layers: [],
        payload: { mode: 'hex', hex: 'ab'.repeat(MAX_PERMALINK_PAYLOAD_BYTES + 1) },
      };
      expect(decodePermalink(encodePermalink(hexOver)).ok).toBe(false);

      // Oversized malformed hex payload is also rejected
      const malformedHexOver: PermalinkState = {
        layers: [],
        payload: { mode: 'hex', hex: 'z'.repeat(MAX_PERMALINK_PAYLOAD_BYTES * 2 + 1) },
      };
      expect(decodePermalink(encodePermalink(malformedHexOver)).ok).toBe(false);
    });

    it('rejects __proto__, constructor, and prototype keys without polluting Object.prototype', () => {
      const ethJson = JSON.stringify(createDefaultEthernet());
      const ipJson = JSON.stringify(createDefaultIPv4());

      const attacks = [
        '{"__proto__":{"polluted":true},"layers":[],"payload":{"mode":"text","text":""}}',
        '{"constructor":{"prototype":{"polluted":true}},"layers":[],"payload":{"mode":"text","text":""}}',
        '{"prototype":{"polluted":true},"layers":[],"payload":{"mode":"text","text":""}}',
        `{"layers":[${ethJson.slice(0, -1)},"__proto__":{"polluted":true}}],"payload":{"mode":"text","text":""}}`,
        `{"layers":[${ipJson.replace('"mf":false}', '"mf":false,"__proto__":{"polluted":true}}')}],"payload":{"mode":"text","text":""}}`,
        `{"layers":[${ethJson.replace('"mode":"auto"}', '"mode":"auto","__proto__":{"polluted":true}}')}],"payload":{"mode":"text","text":""}}`,
        '{"layers":[],"payload":{"mode":"text","text":"ok","constructor":{"polluted":true}}}',
      ];

      for (const raw of attacks) {
        const res = decodePermalink(encodeRawJson(raw));
        expect(res.ok).toBe(false);
      }

      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
  });

  it('builds shareable URLs preserving GitHub Pages sub-path', () => {
    const fragment = encodePermalink({ layers: [], payload: { mode: 'text', text: 'hi' } });
    expect(buildPermalinkUrl('https://shmuto.github.io', '/packet-builder/', fragment)).toBe(
      `https://shmuto.github.io/packet-builder/#${fragment}`,
    );
    expect(buildPermalinkUrl('https://shmuto.github.io', '/packet-builder/', `#${fragment}`)).toBe(
      `https://shmuto.github.io/packet-builder/#${fragment}`,
    );
  });

  it('detects transient NaN numeric drafts via hasOnlyFiniteNumbers', () => {
    const clean: Layer[] = [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()];
    expect(hasOnlyFiniteNumbers(clean)).toBe(true);

    const outOfRange: Layer[] = [{ ...createDefaultIPv4(), ttl: 999 }];
    expect(hasOnlyFiniteNumbers(outOfRange)).toBe(true);

    const blankTtl: Layer[] = [{ ...createDefaultIPv4(), ttl: Number.NaN }];
    expect(hasOnlyFiniteNumbers(blankTtl)).toBe(false);

    const blankManual: Layer[] = [
      { ...createDefaultEthernet(), etherType: manualValue(Number.NaN) },
    ];
    expect(hasOnlyFiniteNumbers(blankManual)).toBe(false);

    const autoEth: Layer[] = [{ ...createDefaultEthernet(), etherType: autoValue() }];
    expect(hasOnlyFiniteNumbers(autoEth)).toBe(true);
  });
});
