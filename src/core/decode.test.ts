import { describe, expect, it } from 'vitest';
import { encodeUtf8, parseHexOrDump, toHexDump, toHexString } from './bytes';
import { decodePacket, detectPrintableUtf8 } from './decode';
import { autoValue, manualValue, type Layer } from './layers/types';
import { buildPacket } from './packet';
import {
  createDefaultARP,
  createDefaultBGP,
  createDefaultEthernet,
  createDefaultICMP,
  createDefaultICMPv6,
  createDefaultIPv4,
  createDefaultIPv6,
  createDefaultTCP,
  createDefaultUDP,
  createDefaultVLAN,
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
    // Unknown EtherType 0x88cc (LLDP)
    const lldpEth = buildPacket(
      [{ ...createDefaultEthernet(), etherType: manualValue(0x88cc) }],
      new Uint8Array([0x02, 0x07, 0x04, 0x00]),
    );
    expect(lldpEth.ok).toBe(true);
    if (lldpEth.ok) {
      const dec = decodePacket(lldpEth.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers).toHaveLength(1);
        expect(dec.value.payload).toEqual(new Uint8Array([0x02, 0x07, 0x04, 0x00]));
        expect(dec.value.notes.some((n) => n.includes('0x88cc'))).toBe(true);
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

  it('round-trips all 4 BGP-4 message types (OPEN, UPDATE, NOTIFICATION, KEEPALIVE) over TCP port 179', () => {
    const tcpToBgp = {
      ...createDefaultTCP(),
      dstPort: 179,
      flags: {
        cwr: false,
        ece: false,
        urg: false,
        ack: true,
        psh: true,
        rst: false,
        syn: false,
        fin: false,
      },
    };
    const tcpFromBgp = { ...tcpToBgp, srcPort: 179, dstPort: 54321 };

    const cases: {
      readonly name: string;
      readonly startLayer: 'ethernet' | 'ipv4';
      readonly layers: Layer[];
      readonly payload: Uint8Array;
    }[] = [
      {
        name: 'OPEN with optional parameters (Ethernet + dstPort 179)',
        startLayer: 'ethernet',
        layers: [createDefaultEthernet(), createDefaultIPv4(), tcpToBgp, createDefaultBGP()],
        // Example Capability Optional Parameter (Type=2, Len=4, CapCode=1, CapLen=2, ...)
        payload: new Uint8Array([0x02, 0x04, 0x01, 0x02, 0x00, 0x01]),
      },
      {
        name: 'UPDATE End-of-RIB (Raw IPv4 + srcPort 179)',
        startLayer: 'ipv4',
        layers: [
          createDefaultIPv4(),
          tcpFromBgp,
          { ...createDefaultBGP(), bgpType: 2 },
        ],
        payload: new Uint8Array(0),
      },
      {
        name: 'UPDATE with path attributes and NLRI',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv4(),
          tcpToBgp,
          {
            ...createDefaultBGP(),
            bgpType: 2,
            totalPathAttrLength: manualValue(4),
          },
        ],
        payload: new Uint8Array([0x40, 0x01, 0x01, 0x00, 0x18, 0xcb, 0x00, 0x71]),
      },
      {
        name: 'NOTIFICATION with error data',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv4(),
          tcpFromBgp,
          { ...createDefaultBGP(), bgpType: 3, errorCode: 2, errorSubcode: 2 },
        ],
        payload: new Uint8Array([0xfe, 0x09]),
      },
      {
        name: 'KEEPALIVE (19B header only)',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv4(),
          tcpToBgp,
          { ...createDefaultBGP(), bgpType: 4 },
        ],
        payload: new Uint8Array(0),
      },
    ];

    for (const tc of cases) {
      const built = buildPacket(tc.layers, tc.payload);
      expect(built.ok, tc.name).toBe(true);
      if (!built.ok) continue;

      const decoded = decodePacket(built.bytes, tc.startLayer);
      expect(decoded.ok, tc.name).toBe(true);
      if (!decoded.ok) continue;
      expect(decoded.value.notes, tc.name).toEqual([]);
      expect(decoded.value.layers.map((l) => l.type), tc.name).toEqual(
        tc.layers.map((l) => l.type),
      );
      expect(decoded.value.payload, tc.name).toEqual(tc.payload);

      const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
      expect(rebuilt.ok, tc.name).toBe(true);
      if (rebuilt.ok) {
        expect(rebuilt.bytes, tc.name).toEqual(built.bytes);
      }
    }
  });

  it('preserves manual BGP Length/Version/OptParmLen and keeps non-179 or truncated BGP as Payload', () => {
    const tcp179 = { ...createDefaultTCP(), dstPort: 179 };

    // Manual BGP Version=3, manual Length=35 (larger than actual 29B), manual OptParmLen=2
    const manualBuilt = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        tcp179,
        {
          ...createDefaultBGP(),
          version: manualValue(3),
          length: manualValue(35),
          optParamLength: manualValue(2),
        },
      ],
      new Uint8Array(0),
    );
    expect(manualBuilt.ok).toBe(true);
    if (manualBuilt.ok) {
      const dec = decodePacket(manualBuilt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        const bgp = dec.value.layers[3];
        expect(bgp.type === 'bgp' && bgp.version).toEqual(manualValue(3));
        expect(bgp.type === 'bgp' && bgp.length).toEqual(manualValue(35));
        expect(bgp.type === 'bgp' && bgp.optParamLength).toEqual(manualValue(2));
        expect(dec.value.notes.some((n) => n.includes('exceeds available TCP payload'))).toBe(true);
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(manualBuilt.bytes);
      }
    }

    // Non-179 TCP port carrying BGP bytes stays as Payload (not decoded as BGP layer)
    const non179Built = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), createDefaultTCP(), createDefaultBGP()],
      new Uint8Array(0),
    );
    expect(non179Built.ok).toBe(true);
    if (non179Built.ok) {
      const dec = decodePacket(non179Built.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv4', 'tcp']);
        expect(dec.value.payload).toHaveLength(29);
      }
    }

    // Truncated BGP OPEN (24 bytes < 29 bytes) on TCP port 179 stays as Payload with a note
    const truncatedOpen = new Uint8Array(24).fill(0xff);
    truncatedOpen[16] = 0x00;
    truncatedOpen[17] = 0x1d;
    truncatedOpen[18] = 0x01; // Type = OPEN
    const truncBuilt = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), tcp179],
      truncatedOpen,
    );
    expect(truncBuilt.ok).toBe(true);
    if (truncBuilt.ok) {
      const dec = decodePacket(truncBuilt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv4', 'tcp']);
        expect(dec.value.notes.some((n) => n.includes('truncated'))).toBe(true);
      }
    }

    // Unknown BGP Type 5 (ROUTE-REFRESH) stays as Payload with a note
    const routeRefresh = new Uint8Array(23).fill(0xff);
    routeRefresh[16] = 0x00;
    routeRefresh[17] = 0x17;
    routeRefresh[18] = 0x05;
    const rrBuilt = buildPacket(
      [createDefaultEthernet(), createDefaultIPv4(), tcp179],
      routeRefresh,
    );
    expect(rrBuilt.ok).toBe(true);
    if (rrBuilt.ok) {
      const dec = decodePacket(rrBuilt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv4', 'tcp']);
        expect(dec.value.notes.some((n) => n.includes('Type 5'))).toBe(true);
      }
    }

    // TCP port 179 segment with TCP options (e.g. Data Offset = 8 / 12-byte RFC 7323 Timestamps) skips BGP decode with a note
    const tcpOptions12B = new Uint8Array([
      0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    ]);
    const keepaliveBytes = new Uint8Array(19).fill(0xff);
    keepaliveBytes[16] = 0x00;
    keepaliveBytes[17] = 0x13;
    keepaliveBytes[18] = 0x04;
    const optPlusBgp = new Uint8Array(tcpOptions12B.length + keepaliveBytes.length);
    optPlusBgp.set(tcpOptions12B, 0);
    optPlusBgp.set(keepaliveBytes, tcpOptions12B.length);

    const tcpOptBgpBuilt = buildPacket(
      [
        createDefaultEthernet(),
        createDefaultIPv4(),
        { ...tcp179, dataOffset: manualValue(8) },
      ],
      optPlusBgp,
    );
    expect(tcpOptBgpBuilt.ok).toBe(true);
    if (tcpOptBgpBuilt.ok) {
      const dec = decodePacket(tcpOptBgpBuilt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv4', 'tcp']);
        expect(dec.value.notes.some((n) => n.includes('BGP-4 decoding skipped'))).toBe(true);
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(tcpOptBgpBuilt.bytes);
      }
    }
  });

  it('decodes and round-trips IP-in-IP (RFC 2003, Protocol 4) and multi-level IPv4 encapsulation', () => {
    // 1) Ethernet + Outer IPv4 + Inner IPv4 + UDP + "Hello"
    const ipipLayers: Layer[] = [
      createDefaultEthernet(),
      { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
      createDefaultIPv4(),
      createDefaultUDP(),
    ];
    const built = buildPacket(ipipLayers, encodeUtf8('Hello'));
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const decoded = decodePacket(built.bytes, 'ethernet');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.notes).toEqual([]);
    expect(decoded.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv4', 'ipv4', 'udp']);
    const outerIp = decoded.value.layers[1];
    const innerIp = decoded.value.layers[2];
    const udp = decoded.value.layers[3];
    expect(outerIp.type === 'ipv4' && outerIp.srcIp).toBe('10.0.0.1');
    expect(outerIp.type === 'ipv4' && outerIp.protocol).toEqual(autoValue());
    expect(innerIp.type === 'ipv4' && innerIp.srcIp).toBe('192.168.0.1');
    expect(udp.type === 'udp' && udp.checksum).toEqual(autoValue());

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok && rebuilt.bytes).toEqual(built.bytes);

    // 2) Raw IPv4 -> IPv4 -> IPv4 -> ICMP (3 nested IPv4 layers)
    const nestedBuilt = buildPacket(
      [
        { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
        { ...createDefaultIPv4(), srcIp: '172.16.0.1', dstIp: '172.16.0.2' },
        createDefaultIPv4(),
        createDefaultICMP(),
      ],
      encodeUtf8('deep'),
    );
    expect(nestedBuilt.ok).toBe(true);
    if (nestedBuilt.ok) {
      const decNested = decodePacket(nestedBuilt.bytes, 'ipv4');
      expect(decNested.ok).toBe(true);
      if (decNested.ok) {
        expect(decNested.value.notes).toEqual([]);
        expect(decNested.value.layers.map((l) => l.type)).toEqual(['ipv4', 'ipv4', 'ipv4', 'icmp']);
        const rebuiltNested = buildPacket(decNested.value.layers, decNested.value.payload);
        expect(rebuiltNested.ok && rebuiltNested.bytes).toEqual(nestedBuilt.bytes);
      }
    }

    // 3) Truncated inner IPv4 (< 20B) and inner IPv4 with options (IHL=6) stay in Payload with notes
    const truncInner = buildPacket(
      [{ ...createDefaultIPv4(), protocol: manualValue(4) }],
      new Uint8Array(10),
    );
    expect(truncInner.ok).toBe(true);
    if (truncInner.ok) {
      const dec = decodePacket(truncInner.bytes, 'ipv4');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ipv4']);
        expect(dec.value.notes.some((n) => n.includes('Protocol 4 is truncated'))).toBe(true);
        const r = buildPacket(dec.value.layers, dec.value.payload);
        expect(r.ok && r.bytes).toEqual(truncInner.bytes);
      }
    }

    const innerWithOptions = new Uint8Array(24);
    innerWithOptions[0] = 0x46; // Version=4, IHL=6
    const optInner = buildPacket(
      [{ ...createDefaultIPv4(), protocol: manualValue(4) }],
      innerWithOptions,
    );
    expect(optInner.ok).toBe(true);
    if (optInner.ok) {
      const dec = decodePacket(optInner.bytes, 'ipv4');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ipv4']);
        expect(dec.value.notes.some((n) => n.includes('Inner IPv4 header') && n.includes('IHL=6'))).toBe(true);
        const r = buildPacket(dec.value.layers, dec.value.payload);
        expect(r.ok && r.bytes).toEqual(optInner.bytes);
      }
    }

    // 4) Inner IPv4 Total Length < outer IPv4 payload length keeps inner + trailing bytes in Payload for exact round-trip
    const innerUdpBuilt = buildPacket(
      [createDefaultIPv4(), createDefaultUDP()],
      new Uint8Array([0xaa, 0xbb]),
    );
    expect(innerUdpBuilt.ok).toBe(true);
    if (innerUdpBuilt.ok) {
      const outerPayloadWithTrailer = new Uint8Array(innerUdpBuilt.bytes.length + 4);
      outerPayloadWithTrailer.set(innerUdpBuilt.bytes, 0);
      outerPayloadWithTrailer.set([0xde, 0xad, 0xbe, 0xef], innerUdpBuilt.bytes.length);
      const outerBuilt = buildPacket(
        [{ ...createDefaultIPv4(), protocol: manualValue(4) }],
        outerPayloadWithTrailer,
      );
      expect(outerBuilt.ok).toBe(true);
      if (outerBuilt.ok) {
        const dec = decodePacket(outerBuilt.bytes, 'ipv4');
        expect(dec.ok).toBe(true);
        if (dec.ok) {
          expect(dec.value.layers.map((l) => l.type)).toEqual(['ipv4']);
          expect(dec.value.layers[0].type === 'ipv4' && dec.value.layers[0].protocol).toEqual(
            manualValue(4),
          );
          expect(dec.value.payload).toEqual(outerPayloadWithTrailer);
          expect(
            dec.value.notes.some((n) => n.includes('Inner IPv4 Total Length')),
          ).toBe(true);
          const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
          expect(rebuilt.ok && rebuilt.bytes).toEqual(outerBuilt.bytes);
        }
      }
    }

    // 5) Ethernet -> Outer IPv4 -> Inner IPv4 -> TCP(179) -> BGP OPEN round-trips byte-for-byte
    const ipipBgpBuilt = buildPacket(
      [
        createDefaultEthernet(),
        { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
        createDefaultIPv4(),
        { ...createDefaultTCP(), dstPort: 179 },
        createDefaultBGP(),
      ],
      new Uint8Array(0),
    );
    expect(ipipBgpBuilt.ok).toBe(true);
    if (ipipBgpBuilt.ok) {
      const dec = decodePacket(ipipBgpBuilt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.notes).toEqual([]);
        expect(dec.value.layers.map((l) => l.type)).toEqual([
          'ethernet',
          'ipv4',
          'ipv4',
          'tcp',
          'bgp',
        ]);
        const tcpLayer = dec.value.layers[3];
        expect(tcpLayer.type === 'tcp' && tcpLayer.checksum).toEqual(autoValue());
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(ipipBgpBuilt.bytes);
      }
    }

    // 6) Pathological nesting (> 16 total IPv4 layers) stops cleanly with a note and round-trips losslessly
    const deepLayers: Layer[] = Array.from({ length: 18 }, () => createDefaultIPv4());
    const deepBuilt = buildPacket(deepLayers, new Uint8Array(0));
    expect(deepBuilt.ok).toBe(true);
    if (deepBuilt.ok) {
      const dec = decodePacket(deepBuilt.bytes, 'ipv4');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers).toHaveLength(16); // MAX_IP_LAYERS = 16 decoded; remaining 2 in Payload
        expect(dec.value.payload).toHaveLength(40);
        expect(dec.value.notes.some((n) => n.includes('IP tunnel layer limit'))).toBe(true);
        const r = buildPacket(dec.value.layers, dec.value.payload);
        expect(r.ok && r.bytes).toEqual(deepBuilt.bytes);
      }
    }
  });

  it('losslessly round-trips IPv6 + UDP/TCP/BGP, 6in4, 4in6, 6in6, and Raw IPv6 packets', () => {
    const cases: readonly {
      readonly name: string;
      readonly startLayer: 'ethernet' | 'ipv4' | 'ipv6';
      readonly layers: readonly Layer[];
      readonly payload: Uint8Array;
    }[] = [
      {
        name: 'Ethernet + IPv6 + UDP + "Hello"',
        startLayer: 'ethernet',
        layers: [createDefaultEthernet(), createDefaultIPv6(), createDefaultUDP()],
        payload: encodeUtf8('Hello'),
      },
      {
        name: 'Ethernet + IPv6 + TCP SYN',
        startLayer: 'ethernet',
        layers: [createDefaultEthernet(), createDefaultIPv6(), createDefaultTCP()],
        payload: new Uint8Array(0),
      },
      {
        name: '6in4 (Ethernet + IPv4 Proto 41 + IPv6 + UDP + "Hello")',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          { ...createDefaultIPv4(), srcIp: '10.0.0.1', dstIp: '10.0.0.2' },
          createDefaultIPv6(),
          createDefaultUDP(),
        ],
        payload: encodeUtf8('Hello'),
      },
      {
        name: '4in6 (Ethernet + IPv6 NH 4 + IPv4 + UDP + "Hello")',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv6(),
          createDefaultIPv4(),
          createDefaultUDP(),
        ],
        payload: encodeUtf8('Hello'),
      },
      {
        name: '6in6 (Ethernet + IPv6 NH 41 + IPv6 + UDP)',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          { ...createDefaultIPv6(), srcIp: '2001:db8:1::1', dstIp: '2001:db8:1::2' },
          createDefaultIPv6(),
          createDefaultUDP(),
        ],
        payload: encodeUtf8('6in6'),
      },
      {
        name: 'Raw IPv6 + UDP',
        startLayer: 'ipv6',
        layers: [
          { ...createDefaultIPv6(), trafficClass: 0x2e, flowLabel: 0xabcde, hopLimit: 255 },
          createDefaultUDP(),
        ],
        payload: encodeUtf8('raw-v6'),
      },
      {
        name: 'IPv6 boundary Flow Label 0xfffff + Traffic Class 0x00 and 0xff',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          { ...createDefaultIPv6(), trafficClass: 0x00, flowLabel: 0xfffff },
          createDefaultUDP(),
        ],
        payload: encodeUtf8('flow-max'),
      },
      {
        name: 'IPv6 boundary Traffic Class 0xff + Flow Label 0xfffff',
        startLayer: 'ipv6',
        layers: [
          { ...createDefaultIPv6(), trafficClass: 0xff, flowLabel: 0xfffff },
          createDefaultUDP(),
        ],
        payload: encodeUtf8('tc-flow-max'),
      },
      {
        name: 'Ethernet + IPv6 + TCP(179) + BGP OPEN',
        startLayer: 'ethernet',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv6(),
          { ...createDefaultTCP(), dstPort: 179 },
          createDefaultBGP(),
        ],
        payload: new Uint8Array(0),
      },
    ];

    for (const tc of cases) {
      const built = buildPacket(tc.layers, tc.payload);
      expect(built.ok, tc.name).toBe(true);
      if (!built.ok) continue;

      const decoded = decodePacket(built.bytes, tc.startLayer);
      expect(decoded.ok, tc.name).toBe(true);
      if (!decoded.ok) continue;

      expect(decoded.value.notes, tc.name).toEqual([]);
      expect(decoded.value.layers.map((l) => l.type), tc.name).toEqual(
        tc.layers.map((l) => l.type),
      );
      expect(decoded.value.payload, tc.name).toEqual(tc.payload);

      const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
      expect(rebuilt.ok, tc.name).toBe(true);
      if (rebuilt.ok) {
        expect(rebuilt.bytes, tc.name).toEqual(built.bytes);
      }
    }

    // Boundary: Raw IPv6 with max Payload Length (65535 bytes) round-trips losslessly
    const maxPayload = new Uint8Array(65535);
    maxPayload[0] = 0xaa;
    maxPayload[65534] = 0x55;
    const maxV6Built = buildPacket(
      [{ ...createDefaultIPv6(), nextHeader: manualValue(59) }],
      maxPayload,
    );
    expect(maxV6Built.ok).toBe(true);
    if (maxV6Built.ok) {
      const dec = decodePacket(maxV6Built.bytes, 'ipv6');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers).toHaveLength(1);
        expect(
          dec.value.layers[0].type === 'ipv6' && dec.value.layers[0].payloadLength,
        ).toEqual(autoValue());
        expect(dec.value.payload).toEqual(maxPayload);
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(maxV6Built.bytes);
      }
    }
  });

  it('keeps IPv6 extension header (Next Header 60) and RFC 2675 Jumbogram shape (Payload Length 0 + NH 0) as Payload with notes and round-trips losslessly', () => {
    const extPayload = new Uint8Array([0x11, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
    const built = buildPacket(
      [
        createDefaultEthernet(),
        { ...createDefaultIPv6(), nextHeader: manualValue(60) },
      ],
      extPayload,
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const decoded = decodePacket(built.bytes, 'ethernet');
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    expect(decoded.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv6']);
    expect(decoded.value.layers[1].type === 'ipv6' && decoded.value.layers[1].nextHeader).toEqual(
      manualValue(60),
    );
    expect(decoded.value.payload).toEqual(extPayload);
    expect(
      decoded.value.notes.some((n) => n.includes('Destination Options') && n.includes('60')),
    ).toBe(true);

    const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
    expect(rebuilt.ok && rebuilt.bytes).toEqual(built.bytes);

    // RFC 2675 §2 Jumbogram shape: Payload Length = 0 + Next Header = 0 (Hop-by-Hop Options)
    // Trailing bytes must NOT be stripped as Ethernet padding.
    const jumboBody = new Uint8Array([0x11, 0x00, 0xc2, 0x04, 0x00, 0x01, 0x00, 0x00]);
    const jumboBuilt = buildPacket(
      [
        createDefaultEthernet(),
        {
          ...createDefaultIPv6(),
          payloadLength: manualValue(0),
          nextHeader: manualValue(0),
        },
      ],
      jumboBody,
    );
    expect(jumboBuilt.ok).toBe(true);
    if (jumboBuilt.ok) {
      const decJumbo = decodePacket(jumboBuilt.bytes, 'ethernet');
      expect(decJumbo.ok).toBe(true);
      if (decJumbo.ok) {
        expect(decJumbo.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv6']);
        expect(
          decJumbo.value.layers[1].type === 'ipv6' && decJumbo.value.layers[1].payloadLength,
        ).toEqual(manualValue(0));
        expect(decJumbo.value.payload).toEqual(jumboBody);
        expect(decJumbo.value.notes.some((n) => n.includes('RFC 2675'))).toBe(true);
        const rebuiltJumbo = buildPacket(decJumbo.value.layers, decJumbo.value.payload);
        expect(rebuiltJumbo.ok && rebuiltJumbo.bytes).toEqual(jumboBuilt.bytes);
      }
    }
  });

  it('handles Ethernet padding on IPv6 frames, manual Payload Length, invalid Raw IPv6, and mixed tunnel depth guard', () => {
    // 1) Ethernet frame padded to 60B carrying 40B IPv6 with Payload Length 0 (6 bytes trailing padding)
    const bareV6 = buildPacket(
      [createDefaultEthernet(), { ...createDefaultIPv6(), nextHeader: manualValue(59) }],
      new Uint8Array(0),
    );
    expect(bareV6.ok).toBe(true);
    if (bareV6.ok) {
      const padded = new Uint8Array(60);
      padded.set(bareV6.bytes, 0);
      const dec = decodePacket(padded, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ethernet', 'ipv6']);
        expect(dec.value.payload).toHaveLength(0);
        expect(
          dec.value.notes.some((n) => n.includes('Ethernet padding beyond IPv6 Payload Length')),
        ).toBe(true);
      }
    }

    // 2) Manual Payload Length mismatch preserved
    const mismatchLen = buildPacket(
      [{ ...createDefaultIPv6(), payloadLength: manualValue(99), nextHeader: manualValue(59) }],
      new Uint8Array([1, 2, 3, 4]),
    );
    expect(mismatchLen.ok).toBe(true);
    if (mismatchLen.ok) {
      const dec = decodePacket(mismatchLen.bytes, 'ipv6');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(
          dec.value.layers[0].type === 'ipv6' && dec.value.layers[0].payloadLength,
        ).toEqual(manualValue(99));
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok).toBe(true);
        if (rebuilt.ok) {
          expect(rebuilt.bytes).toEqual(mismatchLen.bytes);
          expect(rebuilt.warnings.some((w) => w.fieldId === 'payloadLength')).toBe(true);
        }
      }
    }

    // 3) Invalid Raw IPv6 inputs (truncated or wrong version nibble) return err
    expect(decodePacket(new Uint8Array(39), 'ipv6').ok).toBe(false);
    const wrongVersion = new Uint8Array(40);
    wrongVersion[0] = 0x45;
    expect(decodePacket(wrongVersion, 'ipv6').ok).toBe(false);

    // 4) Mixed IPv4/IPv6 nesting (> 16 total IP layers) stops cleanly at depth limit and round-trips
    const mixedDeep: Layer[] = Array.from({ length: 18 }, (_, i) =>
      i % 2 === 0 ? createDefaultIPv6() : createDefaultIPv4(),
    );
    const mixedBuilt = buildPacket(mixedDeep, new Uint8Array(0));
    expect(mixedBuilt.ok).toBe(true);
    if (mixedBuilt.ok) {
      const dec = decodePacket(mixedBuilt.bytes, 'ipv6');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers).toHaveLength(16);
        expect(dec.value.notes.some((n) => n.includes('IP tunnel layer limit'))).toBe(true);
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(mixedBuilt.bytes);
      }
    }
  });

  it('losslessly round-trips ICMPv6 Echo Request, Echo Reply, Packet Too Big, and manually corrupted checksum', () => {
    const cases: readonly {
      readonly name: string;
      readonly layers: readonly Layer[];
      readonly payload: Uint8Array;
      readonly expectAutoChecksum: boolean;
      readonly expectedRestKind: 'echo' | 'raw';
    }[] = [
      {
        name: 'ICMPv6 Echo Request (Type 128)',
        layers: [createDefaultEthernet(), createDefaultIPv6(), createDefaultICMPv6()],
        payload: encodeUtf8('ping'),
        expectAutoChecksum: true,
        expectedRestKind: 'echo',
      },
      {
        name: 'ICMPv6 Echo Reply (Type 129)',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv6(),
          {
            ...createDefaultICMPv6(),
            icmpType: 129,
            rest: { kind: 'echo', identifier: 0x1234, sequence: 0x5678 },
          },
        ],
        payload: encodeUtf8('pong'),
        expectAutoChecksum: true,
        expectedRestKind: 'echo',
      },
      {
        name: 'ICMPv6 Packet Too Big (Type 2, MTU 1280)',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv6(),
          {
            ...createDefaultICMPv6(),
            icmpType: 2,
            code: 0,
            rest: { kind: 'raw', value: 1280 },
          },
        ],
        payload: new Uint8Array([0x60, 0x00, 0x00, 0x00]),
        expectAutoChecksum: true,
        expectedRestKind: 'raw',
      },
      {
        name: 'ICMPv6 Echo Request with manually corrupted checksum (0xdead)',
        layers: [
          createDefaultEthernet(),
          createDefaultIPv6(),
          {
            ...createDefaultICMPv6(),
            checksum: manualValue(0xdead),
          },
        ],
        payload: encodeUtf8('bad'),
        expectAutoChecksum: false,
        expectedRestKind: 'echo',
      },
    ];

    for (const tc of cases) {
      const built = buildPacket(tc.layers, tc.payload);
      expect(built.ok, tc.name).toBe(true);
      if (!built.ok) continue;

      const decoded = decodePacket(built.bytes, 'ethernet');
      expect(decoded.ok, tc.name).toBe(true);
      if (!decoded.ok) continue;

      expect(decoded.value.notes, tc.name).toEqual([]);
      expect(decoded.value.layers.map((l) => l.type), tc.name).toEqual([
        'ethernet',
        'ipv6',
        'icmpv6',
      ]);
      const icmpv6 = decoded.value.layers[2];
      expect(icmpv6.type === 'icmpv6' && icmpv6.rest.kind, tc.name).toBe(tc.expectedRestKind);
      expect(
        icmpv6.type === 'icmpv6' && icmpv6.checksum.mode,
        tc.name,
      ).toBe(tc.expectAutoChecksum ? 'auto' : 'manual');
      expect(decoded.value.payload, tc.name).toEqual(tc.payload);

      const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
      expect(rebuilt.ok, tc.name).toBe(true);
      if (rebuilt.ok) {
        expect(rebuilt.bytes, tc.name).toEqual(built.bytes);
      }
    }

    // Truncated ICMPv6 (< 8 bytes) stays as Payload with a note
    const truncBuilt = buildPacket(
      [{ ...createDefaultIPv6(), nextHeader: manualValue(58) }],
      new Uint8Array([0x80, 0x00, 0x00, 0x00]),
    );
    expect(truncBuilt.ok).toBe(true);
    if (truncBuilt.ok) {
      const dec = decodePacket(truncBuilt.bytes, 'ipv6');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ipv6']);
        expect(dec.value.payload).toEqual(new Uint8Array([0x80, 0x00, 0x00, 0x00]));
        expect(dec.value.notes.some((n) => n.includes('truncated'))).toBe(true);
      }
    }
  });

  it('losslessly round-trips 802.1Q single-tagged, 802.1ad QinQ (0x88a8/0x8100), and legacy QinQ (0x8100/0x8100 and 0x9100/0x8100)', () => {
    const cases: readonly {
      readonly name: string;
      readonly layers: readonly Layer[];
      readonly payload: Uint8Array;
      readonly expectedEthAuto: boolean;
    }[] = [
      {
        name: '802.1Q single-tagged (PCP 5, DEI 1, VID 100 -> IPv4 + UDP)',
        layers: [
          createDefaultEthernet(),
          { ...createDefaultVLAN(), pcp: 5, dei: true, vid: 100 },
          createDefaultIPv4(),
          createDefaultUDP(),
        ],
        payload: encodeUtf8('Hello'),
        expectedEthAuto: true,
      },
      {
        name: '802.1ad QinQ (0x88a8 VID 200 -> 0x8100 VID 100 -> IPv4 + UDP)',
        layers: [
          createDefaultEthernet(),
          { ...createDefaultVLAN(), vid: 200 },
          { ...createDefaultVLAN(), vid: 100 },
          createDefaultIPv4(),
          createDefaultUDP(),
        ],
        payload: encodeUtf8('qinq-8021ad'),
        expectedEthAuto: true,
      },
      {
        name: 'Legacy QinQ (manual 0x8100 / 0x8100)',
        layers: [
          { ...createDefaultEthernet(), etherType: manualValue(0x8100) },
          { ...createDefaultVLAN(), vid: 200 },
          { ...createDefaultVLAN(), vid: 100 },
          createDefaultIPv4(),
          createDefaultUDP(),
        ],
        payload: encodeUtf8('legacy-8100'),
        expectedEthAuto: false,
      },
      {
        name: 'Legacy QinQ (manual 0x9100 / 0x8100 -> IPv6 + ICMPv6)',
        layers: [
          { ...createDefaultEthernet(), etherType: manualValue(0x9100) },
          { ...createDefaultVLAN(), vid: 300 },
          { ...createDefaultVLAN(), vid: 400 },
          createDefaultIPv6(),
          createDefaultICMPv6(),
        ],
        payload: encodeUtf8('legacy-9100'),
        expectedEthAuto: false,
      },
      {
        name: '802.1Q single-tagged ARP',
        layers: [
          { ...createDefaultEthernet(), dstMac: 'ff:ff:ff:ff:ff:ff' },
          { ...createDefaultVLAN(), vid: 10 },
          createDefaultARP(),
        ],
        payload: new Uint8Array(0),
        expectedEthAuto: true,
      },
    ];

    for (const tc of cases) {
      const built = buildPacket(tc.layers, tc.payload);
      expect(built.ok, tc.name).toBe(true);
      if (!built.ok) continue;

      const decoded = decodePacket(built.bytes, 'ethernet');
      expect(decoded.ok, tc.name).toBe(true);
      if (!decoded.ok) continue;

      expect(decoded.value.notes, tc.name).toEqual([]);
      expect(decoded.value.layers.map((l) => l.type), tc.name).toEqual(
        tc.layers.map((l) => l.type),
      );
      expect(
        decoded.value.layers[0].type === 'ethernet' && decoded.value.layers[0].etherType.mode,
        tc.name,
      ).toBe(tc.expectedEthAuto ? 'auto' : 'manual');
      expect(decoded.value.payload, tc.name).toEqual(tc.payload);

      const rebuilt = buildPacket(decoded.value.layers, decoded.value.payload);
      expect(rebuilt.ok, tc.name).toBe(true);
      if (rebuilt.ok) {
        expect(rebuilt.bytes, tc.name).toEqual(built.bytes);
      }
    }

    // Depth guard: > 16 stacked VLAN tags stops cleanly at 16 with note and round-trips losslessly
    const deepVlanLayers: Layer[] = [
      createDefaultEthernet(),
      ...Array.from({ length: 18 }, (_, i) => ({ ...createDefaultVLAN(), vid: i + 1 })),
    ];
    const deepBuilt = buildPacket(deepVlanLayers, new Uint8Array(0));
    expect(deepBuilt.ok).toBe(true);
    if (deepBuilt.ok) {
      const dec = decodePacket(deepBuilt.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        // 1 Ethernet + 16 VLAN tags decoded; remaining 2 tags (8B) kept in Payload
        expect(dec.value.layers).toHaveLength(17);
        expect(dec.value.payload).toHaveLength(8);
        expect(dec.value.notes.some((n) => n.includes('VLAN tag depth limit'))).toBe(true);
        const rebuilt = buildPacket(dec.value.layers, dec.value.payload);
        expect(rebuilt.ok && rebuilt.bytes).toEqual(deepBuilt.bytes);
      }
    }

    // Truncated VLAN tag (< 4 bytes) stays in Payload with a note
    const truncVlan = buildPacket(
      [{ ...createDefaultEthernet(), etherType: manualValue(0x8100) }],
      new Uint8Array([0x00, 0x64]),
    );
    expect(truncVlan.ok).toBe(true);
    if (truncVlan.ok) {
      const dec = decodePacket(truncVlan.bytes, 'ethernet');
      expect(dec.ok).toBe(true);
      if (dec.ok) {
        expect(dec.value.layers.map((l) => l.type)).toEqual(['ethernet']);
        expect(dec.value.payload).toEqual(new Uint8Array([0x00, 0x64]));
        expect(dec.value.notes.some((n) => n.includes('VLAN tag header'))).toBe(true);
      }
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
