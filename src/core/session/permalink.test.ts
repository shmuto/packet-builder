import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from '../bytes';
import {
  buildLegacyPermalinkUrl,
  bytesToBase64Url,
  decodeSessionPermalink,
  EBGP_IPV4_BASIC_SCENARIO,
  encodeSessionPermalink,
  isLegacyPermalinkHash,
  MAX_SESSION_EVENTS,
  MAX_SESSION_ROUTES,
} from './index';

function makeValidPayload(): Record<string, unknown> {
  return JSON.parse(
    JSON.stringify({
      scenarioId: EBGP_IPV4_BASIC_SCENARIO.id,
      config: EBGP_IPV4_BASIC_SCENARIO.config,
      events: EBGP_IPV4_BASIC_SCENARIO.events,
    }),
  ) as Record<string, unknown>;
}

function encodeRawJson(jsonText: string): string {
  return `#s1=${bytesToBase64Url(encodeUtf8(jsonText))}`;
}

function encodePayload(payload: unknown): string {
  return encodeRawJson(JSON.stringify(payload));
}

describe('session permalink (#s1=)', () => {
  it('round-trips a full session config (including optional ipv4NextHop/ipv6NextHop) and event list losslessly', () => {
    const configWithNextHops = {
      ...EBGP_IPV4_BASIC_SCENARIO.config,
      routerA: {
        ...EBGP_IPV4_BASIC_SCENARIO.config.routerA,
        ipv4NextHop: '192.0.2.1',
        ipv6NextHop: '2001:db8::1',
      },
    };
    const fragment = encodeSessionPermalink({
      scenarioId: EBGP_IPV4_BASIC_SCENARIO.id,
      config: configWithNextHops,
      events: EBGP_IPV4_BASIC_SCENARIO.events,
    });
    expect(fragment.startsWith('s1=')).toBe(true);

    const decoded = decodeSessionPermalink(`#${fragment}`);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.value.scenarioId).toBe(EBGP_IPV4_BASIC_SCENARIO.id);
      expect(decoded.value.config).toEqual(configWithNextHops);
      expect(decoded.value.events).toEqual(EBGP_IPV4_BASIC_SCENARIO.events);
    }
  });

  it('rejects malformed #s1=!!!, invalid base64url lengths, invalid UTF-8, and unsupported versions without throwing', () => {
    expect(decodeSessionPermalink('#s1=!!!').ok).toBe(false);
    // Base64url length % 4 === 1 is always invalid
    expect(decodeSessionPermalink('#s1=AAAAA').ok).toBe(false);
    // Invalid UTF-8 byte sequence (0xff 0xfe)
    const invalidUtf8 = `#s1=${bytesToBase64Url(new Uint8Array([0xff, 0xfe, 0x80]))}`;
    expect(decodeSessionPermalink(invalidUtf8).ok).toBe(false);
    expect(decodeSessionPermalink('#s2=e30').ok).toBe(false);
  });

  it.each<{ readonly label: string; readonly hash: string }>([
    {
      label: 'top-level __proto__ key',
      hash: encodeRawJson('{"__proto__":{"polluted":1}}'),
    },
    {
      label: 'nested constructor key',
      hash: encodeRawJson(
        JSON.stringify(makeValidPayload()).replace(
          '"capabilities":{',
          '"capabilities":{"constructor":{},',
        ),
      ),
    },
    {
      label: 'nested prototype key',
      hash: encodeRawJson(
        JSON.stringify(makeValidPayload()).replace(
          '"routerA":{',
          '"routerA":{"prototype":{},',
        ),
      ),
    },
    {
      label: 'unexpected key at root',
      hash: encodePayload({ ...makeValidPayload(), extraRoot: true }),
    },
    {
      label: 'unexpected key at config',
      hash: (() => {
        const p = makeValidPayload();
        (p.config as Record<string, unknown>).extraConfig = 1;
        return encodePayload(p);
      })(),
    },
    {
      label: 'unexpected key at routerA',
      hash: (() => {
        const p = makeValidPayload();
        ((p.config as Record<string, unknown>).routerA as Record<string, unknown>).extraRouter = 1;
        return encodePayload(p);
      })(),
    },
    {
      label: 'unexpected key at capabilities',
      hash: (() => {
        const p = makeValidPayload();
        const rA = (p.config as Record<string, unknown>).routerA as Record<string, unknown>;
        (rA.capabilities as Record<string, unknown>).extraCap = true;
        return encodePayload(p);
      })(),
    },
    {
      label: 'unexpected key at route',
      hash: (() => {
        const p = makeValidPayload();
        const rA = (p.config as Record<string, unknown>).routerA as Record<string, unknown>;
        (rA.routes as Record<string, unknown>[])[0].extraRoute = 'x';
        return encodePayload(p);
      })(),
    },
    {
      label: 'unexpected key at event',
      hash: (() => {
        const p = makeValidPayload();
        (p.events as Record<string, unknown>[])[0].extraEvent = 1;
        return encodePayload(p);
      })(),
    },
    {
      label: `routes exceeding MAX_SESSION_ROUTES (${MAX_SESSION_ROUTES + 1})`,
      hash: (() => {
        const p = makeValidPayload();
        const rA = (p.config as Record<string, unknown>).routerA as Record<string, unknown>;
        rA.routes = Array.from({ length: MAX_SESSION_ROUTES + 1 }, (_, i) => ({
          id: `r${i}`,
          prefix: `203.0.${i}.0/24`,
          origin: 0,
        }));
        return encodePayload(p);
      })(),
    },
    {
      label: `events exceeding MAX_SESSION_EVENTS (${MAX_SESSION_EVENTS + 1})`,
      hash: (() => {
        const p = makeValidPayload();
        p.events = Array.from({ length: MAX_SESSION_EVENTS + 1 }, () => ({ type: 'establish' }));
        return encodePayload(p);
      })(),
    },
    {
      label: 'asn = 0 (below minimum 1)',
      hash: (() => {
        const p = makeValidPayload();
        ((p.config as Record<string, unknown>).routerA as Record<string, unknown>).asn = 0;
        return encodePayload(p);
      })(),
    },
    {
      label: 'float asn (65001.5)',
      hash: (() => {
        const p = makeValidPayload();
        ((p.config as Record<string, unknown>).routerA as Record<string, unknown>).asn = 65001.5;
        return encodePayload(p);
      })(),
    },
    {
      label: 'holdTime = 65536 (exceeds uint16)',
      hash: (() => {
        const p = makeValidPayload();
        ((p.config as Record<string, unknown>).routerA as Record<string, unknown>).holdTime = 65536;
        return encodePayload(p);
      })(),
    },
    {
      label: 'origin = 3 (out of 0..2 range)',
      hash: (() => {
        const p = makeValidPayload();
        const rA = (p.config as Record<string, unknown>).routerA as Record<string, unknown>;
        (rA.routes as Record<string, unknown>[])[0].origin = 3;
        return encodePayload(p);
      })(),
    },
    {
      label: 'unknown event type',
      hash: (() => {
        const p = makeValidPayload();
        p.events = [{ type: 'unknownEvent' }];
        return encodePayload(p);
      })(),
    },
    {
      label: 'invalid event router "C"',
      hash: (() => {
        const p = makeValidPayload();
        p.events = [{ type: 'advertise', router: 'C' }];
        return encodePayload(p);
      })(),
    },
  ])('rejects $label without throwing', ({ hash }) => {
    const result = decodeSessionPermalink(hash);
    expect(result.ok).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('detects legacy #p1= fragments and constructs ./legacy/#p1=... URLs', () => {
    expect(isLegacyPermalinkHash('#p1=abc123')).toBe(true);
    expect(isLegacyPermalinkHash('p1=abc123')).toBe(true);
    expect(isLegacyPermalinkHash('#s1=abc123')).toBe(false);
    expect(buildLegacyPermalinkUrl('#p1=abc123')).toBe('./legacy/#p1=abc123');
  });
});
