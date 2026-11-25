import { describe, expect, it } from 'vitest';
import { buildPacket } from './packet';
import { createPresets } from './presets';

describe('presets', () => {
  it('すべてのプリセットがエラーなしで正しくパケットを組み立てられる', () => {
    const presets = createPresets();
    expect(presets.length).toBeGreaterThanOrEqual(3);

    for (const preset of presets) {
      const result = buildPacket(preset.layers, preset.payloadBytes);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.bytes.length).toBeGreaterThan(0);
      }
    }
  });

  it('UDP と ICMP プリセットは 60 バイト以上で警告ゼロの標準フレームになる', () => {
    const presets = createPresets();
    const udp = presets.find((p) => p.id === 'udp')!;
    const icmp = presets.find((p) => p.id === 'icmp-echo')!;

    const udpResult = buildPacket(udp.layers, udp.payloadBytes);
    expect(udpResult.ok).toBe(true);
    if (udpResult.ok) {
      expect(udpResult.bytes.length).toBeGreaterThanOrEqual(60);
      expect(udpResult.warnings).toHaveLength(0);
    }

    const icmpResult = buildPacket(icmp.layers, icmp.payloadBytes);
    expect(icmpResult.ok).toBe(true);
    if (icmpResult.ok) {
      expect(icmpResult.bytes.length).toBeGreaterThanOrEqual(60);
      expect(icmpResult.warnings).toHaveLength(0);
    }
  });
});
