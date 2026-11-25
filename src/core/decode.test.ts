import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseHexOrDump, toHexDump, toHexString } from './bytes';
import { decodePacket, detectPrintableUtf8 } from './decode';
import { autoValue, manualValue, type Layer } from './layers/types';
import { buildPacket } from './packet';
import {
  createDefaultARP,
  createDefaultEthernet,
  createDefaultIPv4,
  createDefaultTCP,
  createDefaultUDP,
  createPresets,
} from './presets';

describe('decodePacket', () => {
  it('round-trips all built-in presets (UDP, TCP SYN, ICMP Ping, ARP Request) byte-for-byte', () => {
    for (const preset of createPresets()) {
      const built = buildPacket(preset.layers, preset.payloadBytes);
      expect(built.ok).toBe(true);
      if (!built.ok) continue;

      const decoded = decodePacket(built.bytes, 'ethernet');
      expect(decoded.ok).toBe(true);
      if (!decoded.ok) continue;
      expect(decoded.value.notes).toEqual([]);
      expect(decoded.value.layers.map((l) => l.type)).toEqual(preset.layers.map((l) => l.type));

      // Re-encoding decoded layers + payload must match the original bytes identically
      const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
      expect(rebuilt.ok).toBe(true);
      if (!rebuilt.ok) continue;
      expect(rebuilt.bytes).toEqual(built.bytes);
    }
  });

  it('round-trips both compact hex strings and formatted hex dumps', () => {
    const preset = createPresets()[0];
    const built = buildPacket(preset.layers, preset.payloadBytes);
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const fromCompact = parseHexOrDump(toHexString(built.bytes));
    const fromDump = parseHexOrDump(toHexDump(built.bytes));
    expect(fromCompact).toEqual({ ok: true, value: built.bytes });
    expect(fromDump).toEqual({ ok: true, value: built.bytes });

    if (fromDump.ok) {
      const decoded = decodePacket(fromDump.value, 'ethernet');
      expect(decoded.ok).toBe(true);
      if (decoded.ok) {
        const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(built.bytes);
      }
    }
  });

  it('decodes Raw IPv4 packets (startLayer="ipv4") and round-trips identically', () => {
    const layers: Layer[] = [createDefaultIPv4(), createDefaultTCP()];
    const built = buildPacket(layers, encodeUtf8('raw-ipv4'));
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const decoded = decodePacket(built.bytes, 'ipv4');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.layers.map((l) => l.type)).toEqual(['ipv4', 'tcp']);

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok && rebuilt.bytes).toEqual(built.bytes);
  });

  it('marks corrupted checksums and disabled UDP checksum (0x0000) as manual and preserves exact bytes', () => {
    const layers: Layer[] = [
      createDefaultEthernet(),
      { ...createDefaultIPv4(), headerChecksum: manualValue(0xbeef) },
      { ...createDefaultUDP(), checksum: manualValue(0x0000) },
    ];
    const built = buildPacket(layers, encodeUtf8('test'));
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const decoded = decodePacket(built.bytes, 'ethernet');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    const ipv4 = decoded.value.layers[1];
    const udp = decoded.value.layers[2];
    expect(ipv4.type === 'ipv4' && ipv4.headerChecksum).toEqual(manualValue(0xbeef));
    expect(udp.type === 'udp' && udp.checksum).toEqual(manualValue(0x0000));

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok && rebuilt.bytes).toEqual(built.bytes);
  });

  it('preserves Ethernet trailing padding on ARP frames and reports a note', () => {
    const built = buildPacket(
      [{ ...createDefaultEthernet(), dstMac: 'ff:ff:ff:ff:ff:ff' }, createDefaultARP()],
      new Uint8Array(18), // 14 + 28 + 18 = 60B padded Ethernet frame
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const decoded = decodePacket(built.bytes, 'ethernet');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.layers.map((l) => l.type)).toEqual(['ethernet', 'arp']);
    expect(decoded.value.payload).toHaveLength(18);
    expect(decoded.value.notes.length).toBeGreaterThan(0);

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok && rebuilt.bytes).toEqual(built.bytes);
  });

  it('handles unsupported EtherType, unsupported IPv4 protocol, and TCP options gracefully with notes', () => {
    // Unknown EtherType 0x86dd (IPv6)
    const ipv6Eth = buildPacket(
      [{ ...createDefaultEthernet(), etherType: manualValue(0x86dd) }],
      new Uint8Array([0x60, 0x00, 0x00, 0x00]),
    );
    expect(ipv6Eth.ok).toBe(true);
    if (ipv6Eth.ok) {
      const dec = decodePacket(ipv6Eth.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers).toHaveLength(1);
        expect(dec.value.payload).toEqual(new Uint8Array([0x60, 0x00, 0x00, 0x00]));
        expect(dec.value.notes.some((n) => n.includes('0x86dd'))).toBe(true);
      }
    }

    // TCP with Data Offset = 6 (options present)
    const tcpWithOpt = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        { ...createDefaultTCP(), dataOffset: manualValue(6), checksum: autoValue() },
      ],
      new Uint8Array([0x01, 0x01, 0x08, 0x0a]),
    );
    expect(tcpWithOpt.ok).toBe(true);
    if (tcpWithOpt.ok) {
      const dec = decodePacket(tcpWithOpt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.notes.some((n) => n.includes('Data Offset'))).toBe(true);
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(tcpWithOpt.bytes);
      }
    }
  });

  it('returns descriptive errors for empty, truncated, or unsupported Raw IPv4 inputs', () => {
    expect(decodePacket(new Uint8Array(0), 'ethernet').ok).toBe(false);
    expect(decodePacket(new Uint8Array(13), 'ethernet').ok).toBe(false);
    expect(decodePacket(new Uint8Array(19), 'ipv4').ok).toBe(false);

    // Version = 6 passed to Raw IPv4 decoder
    const wrongVer = new Uint8Array(20);
    wrongVer[0] = 0x65;
    expect(decodePacket(wrongVer, 'ipv4').ok).toBe(false);

    // IHL = 6 (IPv4 options) passed to Raw IPv4 decoder
    const withOptions = new Uint8Array(24);
    withOptions[0] = 0x46;
    expect(decodePacket(withOptions, 'ipv4').ok).toBe(false);
  });

  it('strips Ethernet zero-padding on 60-byte TCP SYN and UDP frames and keeps checksums auto', () => {
    // 1) TCP SYN (54 bytes) + 6 bytes of 0x00 Ethernet padding = 60-byte wire frame
    const tcpBuilt = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
      new Uint8Array(0),
    );
    expect(tcpBuilt.ok).toBe(true);
    if (!tcpBuilt.ok) return;

    const paddedTcp = new Uint8Array(60);
    paddedTcp.set(tcpBuilt.bytes, 0);

    const decTcp = decodePacket(paddedTcp, 'ethernet');
    expect(decTcp.ok).toBe(true);
    if (!decTcp.ok) return;
    expect(decTcp.value.payload).toHaveLength(0);
    expect(decTcp.value.notes.some((n) => n.includes('6 trailing zero byte(s)'))).toBe(true);
    const tcpIp = decTcp.value.layers[1];
    const tcpL4 = decTcp.value.layers[2];
    expect(tcpIp.type === 'ipv4' && tcpIp.totalLength).toEqual(autoValue());
    expect(tcpL4.type === 'tcp' && tcpL4.checksum).toEqual(autoValue());

    const rebuiltTcp = buildPacket(decTcp.value.layers, decTcp.value.payload);
    expect(rebuiltTcp.ok && rebuiltTcp.bytes).toEqual(tcpBuilt.bytes);

    // 2) Short UDP frame (14 + 20 + 8 + 4 = 46 bytes) + 14 bytes of 0x00 padding = 60-byte wire frame
    const udpBuilt = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultUDP()],
      encodeUtf8('ping'),
    );
    expect(udpBuilt.ok).toBe(true);
    if (!udpBuilt.ok) return;

    const paddedUdp = new Uint8Array(60);
    paddedUdp.set(udpBuilt.bytes, 0);

    const decUdp = decodePacket(paddedUdp, 'ethernet');
    expect(decUdp.ok).toBe(true);
    if (!decUdp.ok) return;
    expect(decUdp.value.payload).toEqual(encodeUtf8('ping'));
    expect(decUdp.value.notes.some((n) => n.includes('14 trailing zero byte(s)'))).toBe(true);
    const udpIp = decUdp.value.layers[1];
    const udpL4 = decUdp.value.layers[2];
    expect(udpIp.type === 'ipv4' && udpIp.totalLength).toEqual(autoValue());
    expect(udpL4.type === 'udp' && udpL4.length).toEqual(autoValue());
    expect(udpL4.type === 'udp' && udpL4.checksum).toEqual(autoValue());

    // 3) Non-zero (0xaa) Ethernet padding on a 60-byte TCP SYN frame also keeps TCP Checksum auto
    const nonZeroPaddedTcp = new Uint8Array(60).fill(0xaa);
    nonZeroPaddedTcp.set(tcpBuilt.bytes, 0);
    const decNonZero = decodePacket(nonZeroPaddedTcp, 'ethernet');
    expect(decNonZero.ok).toBe(true);
    if (!decNonZero.ok) return;
    expect(decNonZero.value.payload).toHaveLength(0);
    expect(decNonZero.value.notes.some((n) => n.includes('6 trailing non-zero byte(s)'))).toBe(
      true,
    );
    const nzTcp = decNonZero.value.layers[2];
    expect(nzTcp.type === 'tcp' && nzTcp.checksum).toEqual(autoValue());
  });

  it('does not decode upper-layer headers for non-initial IPv4 fragments (Fragment Offset > 0)', () => {
    const fragBuilt = buildPacket(
      [
        createDefaultEthernet(),
        { ...createDefaultIPv4(), fragmentOffset: 185, protocol: manualValue(17) },
      ],
      new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]),
    );
    expect(fragBuilt.ok).toBe(true);
    if (!fragBuilt.ok) return;

    const decoded = decodePacket(fragBuilt.bytes, 'ethernet');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv4']);
    expect(decoded.value.payload).toEqual(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]),
    );
    expect(decoded.value.notes.some((n) => n.includes('Non-initial IPv4 fragment'))).toBe(true);

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok && rebuilt.bytes).toEqual(fragBuilt.bytes);
  });

  it('emits an explicit note when TCP Reserved bits are non-zero', () => {
    const built = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP()],
      new Uint8Array(0),
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    // Set TCP Reserved LSB (byte 12 of TCP header = packet byte 46: 0x50 -> 0x51)
    const modified = new Uint8Array(built.bytes);
    modified[46] = 0x51;

    const decoded = decodePacket(modified, 'ethernet');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(
      decoded.value.notes.some(
        (n) => n.includes('TCP Reserved bits') && n.includes('will differ'),
      ),
    ).toBe(true);

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok).toBe(true);
    if (rebuilt.ok) {
      // Encoder resets Reserved to 0 (0x50), so re-encoded byte 46 differs from 0x51
      expect(rebuilt.bytes[46]).toBe(0x50);
    }
  });
});

describe('detectPrintableUtf8', () => {
  it('accepts empty and printable UTF-8 text and rejects binary or BOM-prefixed bytes', () => {
    expect(detectPrintableUtf8(new Uint8Array(0))).toEqual({ printable: true, text: '' });
    expect(detectPrintableUtf8(encodeUtf8('Hello\n\tWorld!'))).toEqual({
      printable: true,
      text: 'Hello\n\tWorld!',
    });
    expect(detectPrintableUtf8(new Uint8Array([0x00, 0x01, 0x02]))).toEqual({ printable: false });
    expect(detectPrintableUtf8(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toEqual({
      printable: false,
    });
    expect(detectPrintableUtf8(new Uint8Array([0xef, 0xbb, 0xbf, 0x41]))).toEqual({
      printable: false,
    });
  });
});
