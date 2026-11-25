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

  it('ARP Request プリセットはブロードキャスト宛先・EtherType 0x0806・42 バイトフレームを生成する', () => {
    const arpPreset = createPresets().find((p) => p.id === 'arp-request');
    expect(arpPreset).toBeDefined();
    if (!arpPreset) return;

    const result = buildPacket(arpPreset.layers, arpPreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.bytes.length).toBe(42);
    // Destination MAC = ff:ff:ff:ff:ff:ff
    expect(result.bytes.slice(0, 6)).toEqual(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
    // EtherType = 0x0806 (ARP)
    expect(result.bytes.slice(12, 14)).toEqual(new Uint8Array([0x08, 0x06]));
    // ARP Operation = 1 (Request)
    expect(result.bytes.slice(20, 22)).toEqual(new Uint8Array([0x00, 0x01]));
  });
});
