import { describe, expect, it } from 'vitest';
import { encodeUtf8 } from '../bytes';
import {
  buildLegacyPermalinkUrl,
  bytesToBase64Url,
  decodeSessionPermalink,
  EBGP_IPV4_BASIC_SCENARIO,
  encodeSessionPermalink,
  isLegacyPermalinkHash,
} from './index';

describe('session permalink (#s1=)', () => {
  it('round-trips a full session config and event list losslessly', () => {
    const fragment = encodeSessionPermalink({
      scenarioId: EBGP_IPV4_BASIC_SCENARIO.id,
      config: EBGP_IPV4_BASIC_SCENARIO.config,
      events: EBGP_IPV4_BASIC_SCENARIO.events,
    });
    expect(fragment.startsWith('s1=')).toBe(true);

    const decoded = decodeSessionPermalink(`#${fragment}`);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.value.scenarioId).toBe(EBGP_IPV4_BASIC_SCENARIO.id);
      expect(decoded.value.config).toEqual(EBGP_IPV4_BASIC_SCENARIO.config);
      expect(decoded.value.events).toEqual(EBGP_IPV4_BASIC_SCENARIO.events);
    }
  });

  it('rejects malformed #s1=!!! and prototype-pollution payloads without throwing', () => {
    const malformed = decodeSessionPermalink('#s1=!!!');
    expect(malformed.ok).toBe(false);

    const protoPayload = `s1=${bytesToBase64Url(encodeUtf8('{"__proto__":{"polluted":1}}'))}`;
    const protoResult = decodeSessionPermalink(`#${protoPayload}`);
    expect(protoResult.ok).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    const wrongVersion = decodeSessionPermalink('#s2=e30');
    expect(wrongVersion.ok).toBe(false);
  });

  it('detects legacy #p1= fragments and constructs ./legacy/#p1=... URLs', () => {
    expect(isLegacyPermalinkHash('#p1=abc123')).toBe(true);
    expect(isLegacyPermalinkHash('p1=abc123')).toBe(true);
    expect(isLegacyPermalinkHash('#s1=abc123')).toBe(false);
    expect(buildLegacyPermalinkUrl('#p1=abc123')).toBe('./legacy/#p1=abc123');
  });
});
