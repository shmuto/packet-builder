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

  it('BGP OPEN preset builds an 83-byte RFC 4271 frame over TCP port 179 with zero warnings', () => {
    const bgpPreset = createPresets().find((p) => p.id === 'bgp-open');
    expect(bgpPreset).toBeDefined();
    if (!bgpPreset) return;

    const result = buildPacket(bgpPreset.layers, bgpPreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Ethernet) + 20(IPv4) + 20(TCP) + 29(BGP OPEN) = 83 bytes
    expect(result.bytes.length).toBe(83);
    expect(result.warnings).toHaveLength(0);
    // TCP Destination Port = 179 (0x00b3) at offset 36..37
    expect(result.bytes.slice(36, 38)).toEqual(new Uint8Array([0x00, 0xb3]));
    // BGP Marker = 16 bytes of 0xff at offset 54..69
    expect(result.bytes.slice(54, 70)).toEqual(new Uint8Array(16).fill(0xff));
    // BGP Length = 29 (0x001d), Type = 1 (OPEN), Version = 4
    expect(result.bytes.slice(70, 74)).toEqual(new Uint8Array([0x00, 0x1d, 0x01, 0x04]));
  });

  it('IPv6 UDP preset builds a 67-byte RFC 8200 frame with EtherType 0x86dd and zero warnings', () => {
    const ipv6Preset = createPresets().find((p) => p.id === 'udp-ipv6');
    expect(ipv6Preset).toBeDefined();
    if (!ipv6Preset) return;

    const result = buildPacket(ipv6Preset.layers, ipv6Preset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Ethernet) + 40(IPv6) + 8(UDP) + 5("Hello") = 67 bytes
    expect(result.bytes.length).toBe(67);
    expect(result.warnings).toHaveLength(0);
    // EtherType = 0x86dd (IPv6)
    expect(result.bytes.slice(12, 14)).toEqual(new Uint8Array([0x86, 0xdd]));
    // IPv6 Version=6, Payload Length=13 (0x000d), Next Header=17 (UDP), Hop Limit=64
    expect(result.bytes.slice(14, 22)).toEqual(
      new Uint8Array([0x60, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x11, 0x40]),
    );
  });

  it('IPv6 Ping preset builds a 66-byte RFC 4443 frame with Next Header 58 and zero warnings', () => {
    const pingV6 = createPresets().find((p) => p.id === 'icmpv6-echo');
    expect(pingV6).toBeDefined();
    if (!pingV6) return;

    const result = buildPacket(pingV6.layers, pingV6.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Ethernet) + 40(IPv6) + 8(ICMPv6) + 4("ping") = 66 bytes
    expect(result.bytes.length).toBe(66);
    expect(result.warnings).toHaveLength(0);
    // IPv6 Next Header = 58 (0x3a, ICMPv6) at offset 20
    expect(result.bytes[20]).toBe(58);
    // ICMPv6 Type=128 (0x80), Code=0, Checksum=0x4571, ID=1, Seq=1 at offset 54..61
    expect(result.bytes.slice(54, 62)).toEqual(
      new Uint8Array([0x80, 0x00, 0x45, 0x71, 0x00, 0x01, 0x00, 0x01]),
    );
  });

  it('VLAN UDP preset builds a 60-byte 802.1Q frame (VID 100, TPID 0x8100) with zero warnings', () => {
    const vlanPreset = createPresets().find((p) => p.id === 'vlan-udp');
    expect(vlanPreset).toBeDefined();
    if (!vlanPreset) return;

    const result = buildPacket(vlanPreset.layers, vlanPreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Ethernet) + 4(VLAN) + 20(IPv4) + 8(UDP) + 14("Hello, VLAN!!!") = 60 bytes
    expect(result.bytes.length).toBe(60);
    expect(result.warnings).toHaveLength(0);
    // Ethernet TPID = 0x8100, VLAN TCI = 0x0064 (VID 100), Inner EtherType = 0x0800
    expect(result.bytes.slice(12, 18)).toEqual(new Uint8Array([0x81, 0x00, 0x00, 0x64, 0x08, 0x00]));
  });
});
