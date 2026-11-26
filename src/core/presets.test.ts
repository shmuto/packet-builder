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

  it('GRE Tunnel preset builds a 74-byte RFC 2784 frame (Outer IPv4 Proto 47 + GRE + Inner IPv4 + ICMP) with zero warnings', () => {
    const grePreset = createPresets().find((p) => p.id === 'gre-ipv4');
    expect(grePreset).toBeDefined();
    if (!grePreset) return;

    const result = buildPacket(grePreset.layers, grePreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Eth) + 20(Outer IPv4) + 4(GRE) + 20(Inner IPv4) + 8(ICMP) + 8("gre-ping") = 74 bytes
    expect(result.bytes.length).toBe(74);
    expect(result.warnings).toHaveLength(0);
    // Outer IPv4 Protocol = 47 (GRE) at offset 23
    expect(result.bytes[23]).toBe(47);
    // GRE base header at offset 34..37: 00 00 08 00 (IPv4)
    expect(result.bytes.slice(34, 38)).toEqual(new Uint8Array([0x00, 0x00, 0x08, 0x00]));
  });

  it('VXLAN Overlay preset builds a 92-byte RFC 7348 frame (UDP 4789 + VXLAN VNI 100 + Inner Ethernet + ARP) with zero VXLAN warnings', () => {
    const vxlanPreset = createPresets().find((p) => p.id === 'vxlan');
    expect(vxlanPreset).toBeDefined();
    if (!vxlanPreset) return;

    const result = buildPacket(vxlanPreset.layers, vxlanPreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Eth) + 20(IPv4) + 8(UDP) + 8(VXLAN) + 14(Inner Eth) + 28(ARP) = 92 bytes
    expect(result.bytes.length).toBe(92);
    expect(result.warnings.filter((w) => w.layerIndex !== 4)).toHaveLength(0);
    // Outer UDP dstPort = 4789 (0x12b5) at offset 36..37
    expect(result.bytes.slice(36, 38)).toEqual(new Uint8Array([0x12, 0xb5]));
    // VXLAN header at offset 42..49: 08 00 00 00 00 00 64 00
    expect(result.bytes.slice(42, 50)).toEqual(
      new Uint8Array([0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00]),
    );
  });

  it('TCP SYN preset builds a 74-byte Linux-style SYN frame with 20B TCP options, Data Offset 0xa, and zero warnings', () => {
    const tcpSynPreset = createPresets().find((p) => p.id === 'tcp-syn');
    expect(tcpSynPreset).toBeDefined();
    if (!tcpSynPreset) return;

    const result = buildPacket(tcpSynPreset.layers, tcpSynPreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Eth) + 20(IPv4) + 40(TCP: 20 base + 20 options) = 74 bytes
    expect(result.bytes.length).toBe(74);
    expect(result.warnings).toHaveLength(0);
    // TCP starts at offset 34: Data Offset = 0xa at offset 46, Checksum = 0xaa88 at offset 50..51
    expect(result.bytes[46] >>> 4).toBe(0xa);
    expect(result.bytes.slice(50, 52)).toEqual(new Uint8Array([0xaa, 0x88]));
    // Options at offset 54..73: MSS 1460, SACK-Permitted, Timestamps(1000000, 0), NOP, WScale 7
    expect(result.bytes.slice(54, 74)).toEqual(
      new Uint8Array([
        0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02,
        0x08, 0x0a, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x01,
        0x03, 0x03, 0x07,
      ]),
    );
  });

  it('IGMPv2 (Router Alert) preset builds a 46-byte frame with IHL 6, TTL 1, Protocol 2, Router Alert 94 04 00 00, and IGMPv2 payload', () => {
    const igmpPreset = createPresets().find((p) => p.id === 'igmp-router-alert');
    expect(igmpPreset).toBeDefined();
    if (!igmpPreset) return;

    const result = buildPacket(igmpPreset.layers, igmpPreset.payloadBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // 14(Eth) + 24(IPv4 IHL=6 with Router Alert) + 8(IGMPv2 General Query) = 46 bytes
    expect(result.bytes.length).toBe(46);
    // IPv4 starts at offset 14: Version=4, IHL=6 (0x46), Total Length=32 (0x0020), TTL=1, Protocol=2, Checksum=0x31f9
    expect(result.bytes[14]).toBe(0x46);
    expect(result.bytes.slice(16, 18)).toEqual(new Uint8Array([0x00, 0x20]));
    expect(result.bytes[22]).toBe(1);
    expect(result.bytes[23]).toBe(2);
    expect(result.bytes.slice(24, 26)).toEqual(new Uint8Array([0x31, 0xf9]));
    // Router Alert option at offset 34..37: 94 04 00 00
    expect(result.bytes.slice(34, 38)).toEqual(new Uint8Array([0x94, 0x04, 0x00, 0x00]));
    // IGMPv2 General Query payload at offset 38..45
    expect(result.bytes.slice(38, 46)).toEqual(
      new Uint8Array([0x11, 0x64, 0xee, 0x9b, 0x00, 0x00, 0x00, 0x00]),
    );
  });
});
