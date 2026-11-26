import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseHexBytes, toHexString } from '../bytes';
import {
  afiSafiKey,
  BGP_AFI,
  BGP_AS_TRANS,
  BGP_SAFI,
  createEndOfRib,
  decodeBgpHex,
  decodeBgpMessages,
  encodeBgpMessage,
  encodeBgpMessages,
  formatCommunity,
  isEndOfRib,
  makeCommunity,
  parseCidrPrefix,
  WELL_KNOWN_COMMUNITIES,
  type BgpCodecContext,
  type BgpMessage,
  type BgpNotificationMessage,
  type BgpOpenMessage,
  type BgpRouteRefreshMessage,
  type BgpUpdateMessage,
  type DissectionNode,
} from './index';

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const MARKER_HEX = 'ff'.repeat(16);

function hex(spaced: string): string {
  return spaced.replace(/\s+/g, '').toLowerCase();
}

function collectLeaves(node: DissectionNode, out: DissectionNode[] = []): DissectionNode[] {
  if (!node.children || node.children.length === 0) {
    out.push(node);
  } else {
    for (const child of node.children) {
      collectLeaves(child, out);
    }
  }
  return out;
}

function assertValidDissectionTree(root: DissectionNode, totalBytes: number): void {
  const walk = (node: DissectionNode, parent: DissectionNode | null) => {
    expect(node.label.trim().length, `empty label on ${node.id}`).toBeGreaterThan(0);
    expect(node.explanation.trim().length, `empty explanation on ${node.id}`).toBeGreaterThan(0);
    expect(node.reference.trim().length, `empty reference on ${node.id}`).toBeGreaterThan(0);
    expect(node.byteRange.start, `invalid start on ${node.id}`).toBeGreaterThanOrEqual(0);
    expect(node.byteRange.end, `end < start on ${node.id}`).toBeGreaterThanOrEqual(
      node.byteRange.start,
    );
    expect(node.byteRange.end, `end > totalBytes on ${node.id}`).toBeLessThanOrEqual(totalBytes);

    if (parent !== null) {
      expect(
        node.byteRange.start,
        `child ${node.id} starts before parent ${parent.id}`,
      ).toBeGreaterThanOrEqual(parent.byteRange.start);
      expect(
        node.byteRange.end,
        `child ${node.id} ends after parent ${parent.id}`,
      ).toBeLessThanOrEqual(parent.byteRange.end);
    }

    if (node.children) {
      for (const child of node.children) {
        walk(child, node);
      }
    }
  };

  expect(root.byteRange).toEqual({ start: 0, end: totalBytes });
  walk(root, null);

  const nonEmptyLeaves = collectLeaves(root)
    .filter((leaf) => leaf.byteRange.end > leaf.byteRange.start)
    .sort((a, b) => a.byteRange.start - b.byteRange.start);

  expect(nonEmptyLeaves.length).toBeGreaterThan(0);
  expect(nonEmptyLeaves[0].byteRange.start).toBe(0);
  for (let i = 1; i < nonEmptyLeaves.length; i++) {
    expect(
      nonEmptyLeaves[i].byteRange.start,
      `gap or overlap between ${nonEmptyLeaves[i - 1].id} and ${nonEmptyLeaves[i].id}`,
    ).toBe(nonEmptyLeaves[i - 1].byteRange.end);
  }
  expect(nonEmptyLeaves[nonEmptyLeaves.length - 1].byteRange.end).toBe(totalBytes);
}

function assertLosslessRoundTrip(msg: BgpMessage, ctx: BgpCodecContext): Uint8Array {
  const encoded = encodeBgpMessage(msg, ctx);
  expect(encoded.ok).toBe(true);
  if (!encoded.ok) throw new Error(encoded.error);

  assertValidDissectionTree(encoded.value.tree, encoded.value.bytes.length);

  const decoded = decodeBgpMessages(encoded.value.bytes, ctx);
  expect(decoded.unparsedBytes.length).toBe(0);
  expect(decoded.notes).toEqual([]);
  expect(decoded.messages).toHaveLength(1);
  assertValidDissectionTree(decoded.messages[0].tree, encoded.value.bytes.length);

  const reEncoded = encodeBgpMessage(decoded.messages[0].message, ctx);
  expect(reEncoded.ok).toBe(true);
  if (!reEncoded.ok) throw new Error(reEncoded.error);
  expect(toHexString(reEncoded.value.bytes)).toBe(toHexString(encoded.value.bytes));

  return encoded.value.bytes;
}

describe('BGP core codec and dissection tree', () => {
  it('encodes and decodes OPEN with MP IPv4/IPv6, Route Refresh, and 4-octet AS 65551 -> My AS 23456', () => {
    const openMsg: BgpOpenMessage = {
      type: 'open',
      version: 4,
      asn: 65551, // 0x0001000f > 65535 -> My AS auto-fills with AS_TRANS (23456 = 0x5ba0)
      holdTime: 90, // 0x005a
      bgpIdentifier: '192.0.2.1', // c0 00 02 01
      capabilities: [
        { kind: 'mp', afi: BGP_AFI.IPV4, safi: BGP_SAFI.UNICAST }, // 01 04 00 01 00 01 (6B)
        { kind: 'mp', afi: BGP_AFI.IPV6, safi: BGP_SAFI.UNICAST }, // 01 04 00 02 00 01 (6B)
        { kind: 'routeRefresh' }, // 02 00 (2B)
        { kind: 'fourOctetAs', asn: 65551 }, // 41 04 00 01 00 0f (6B)
      ],
    };

    // Byte arithmetic:
    //   Header (19B): Marker (16B ff) + Length 51 (00 33) + Type OPEN (01)
    //   OPEN fixed (10B): Version (04) + My AS 23456 (5b a0) + Hold 90 (00 5a)
    //                     + BGP ID 192.0.2.1 (c0 00 02 01) + Opt Parm Len 22 (16)
    //   Opt Param Type 2 (2 + 20 = 22B): Type (02) + Len 20 (14)
    //     + Cap 1 MP IPv4 Unicast (01 04 00 01 00 01)        = 6B
    //     + Cap 1 MP IPv6 Unicast (01 04 00 02 00 01)        = 6B
    //     + Cap 2 Route Refresh   (02 00)                    = 2B
    //     + Cap 65 4-octet AS     (41 04 00 01 00 0f)        = 6B
    //   Total = 19 + 10 + 22 = 51 bytes (0x0033)
    const expectedHex = hex(`
      ${MARKER_HEX} 00 33 01
      04 5b a0 00 5a c0 00 02 01 16
      02 14
      01 04 00 01 00 01
      01 04 00 02 00 01
      02 00
      41 04 00 01 00 0f
    `);

    const bytes = assertLosslessRoundTrip(openMsg, { fourOctetAs: true });
    expect(toHexString(bytes)).toBe(expectedHex);

    const encoded = encodeBgpMessage(openMsg);
    expect(encoded.ok).toBe(true);
    if (encoded.ok) {
      const myAsNode = encoded.value.tree.children?.find((n) => n.id === 'open.myAs');
      expect(myAsNode?.value).toContain(String(BGP_AS_TRANS));
      expect(myAsNode?.explanation).toContain('AS_TRANS');
    }
  });

  it('encodes and decodes IPv4 UPDATE with 2-byte and 4-byte AS_PATH encoding', () => {
    const updateMsg: BgpUpdateMessage = {
      type: 'update',
      withdrawnRoutes: [],
      pathAttributes: [
        { kind: 'origin', origin: 0 }, // 40 01 01 00 (4B)
        { kind: 'asPath', segments: [{ type: 2, asns: [65001] }] }, // 65001 = 0xfde9
        { kind: 'nextHop', nextHop: '192.0.2.1' }, // 40 03 04 c0 00 02 01 (7B)
        { kind: 'med', med: 50 }, // 80 04 04 00 00 00 32 (7B)
        { kind: 'communities', communities: [makeCommunity(65001, 100)] }, // c0 08 04 fd e9 00 64 (7B)
      ],
      nlri: [{ prefix: '203.0.113.0/24' }], // 18 cb 00 71 (4B)
    };

    // 2-byte AS context (fourOctetAs: false):
    //   AS_PATH = 40 02 04 02 01 fd e9 (7B)
    //   Total Path Attr Len = 4 + 7 + 7 + 7 + 7 = 32 (0x0020)
    //   Total Message Len = 19 + 2 (withdrawn len) + 2 (attr len) + 32 + 4 (NLRI) = 59 (0x003b)
    const expected2Byte = hex(`
      ${MARKER_HEX} 00 3b 02
      00 00
      00 20
      40 01 01 00
      40 02 04 02 01 fd e9
      40 03 04 c0 00 02 01
      80 04 04 00 00 00 32
      c0 08 04 fd e9 00 64
      18 cb 00 71
    `);
    const bytes2 = assertLosslessRoundTrip(updateMsg, { fourOctetAs: false });
    expect(toHexString(bytes2)).toBe(expected2Byte);

    // 4-byte AS context (fourOctetAs: true):
    //   AS_PATH = 40 02 06 02 01 00 00 fd e9 (9B)
    //   Total Path Attr Len = 4 + 9 + 7 + 7 + 7 = 34 (0x0022)
    //   Total Message Len = 19 + 2 + 2 + 34 + 4 = 61 (0x003d)
    const expected4Byte = hex(`
      ${MARKER_HEX} 00 3d 02
      00 00
      00 22
      40 01 01 00
      40 02 06 02 01 00 00 fd e9
      40 03 04 c0 00 02 01
      80 04 04 00 00 00 32
      c0 08 04 fd e9 00 64
      18 cb 00 71
    `);
    const bytes4 = assertLosslessRoundTrip(updateMsg, { fourOctetAs: true });
    expect(toHexString(bytes4)).toBe(expected4Byte);
  });

  it('encodes and decodes an IPv6 UPDATE using MP_REACH_NLRI', () => {
    const ipv6Update: BgpUpdateMessage = {
      type: 'update',
      withdrawnRoutes: [],
      pathAttributes: [
        { kind: 'origin', origin: 0 }, // 40 01 01 00 (4B)
        { kind: 'asPath', segments: [{ type: 2, asns: [65001] }] }, // 40 02 06 02 01 00 00 fd e9 (9B)
        {
          kind: 'mpReachNlri',
          afi: BGP_AFI.IPV6,
          safi: BGP_SAFI.UNICAST,
          nextHops: ['2001:db8::1'],
          nlri: [{ prefix: '2001:db8:1::/48' }],
        },
      ],
      nlri: [],
    };

    // Byte arithmetic:
    //   MP_REACH_NLRI value:
    //     AFI 2 (00 02) + SAFI 1 (01) + NH Len 16 (10) = 4B
    //     NH 2001:db8::1 (20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01) = 16B
    //     Reserved (00) = 1B
    //     NLRI 2001:db8:1::/48 -> len 48 (30) + 6 octets (20 01 0d b8 00 01) = 7B
    //     Value len = 28 (0x1c); attr header (80 0e 1c) = 3B -> total attr = 31B
    //   Total Path Attr Len = 4 + 9 + 31 = 44 (0x002c)
    //   Total Message Len = 19 + 2 + 2 + 44 = 67 (0x0043)
    const expectedHex = hex(`
      ${MARKER_HEX} 00 43 02
      00 00
      00 2c
      40 01 01 00
      40 02 06 02 01 00 00 fd e9
      80 0e 1c
      00 02 01 10
      20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
      00
      30 20 01 0d b8 00 01
    `);

    const bytes = assertLosslessRoundTrip(ipv6Update, { fourOctetAs: true });
    expect(toHexString(bytes)).toBe(expectedHex);
  });

  it('encodes and decodes both End-of-RIB forms (IPv4 unicast 23B and IPv6 unicast 29B)', () => {
    // IPv4 unicast EoR: 19B header + 2B withdrawn=0 + 2B pathAttr=0 = 23B (0x0017)
    const ipv4Eor = createEndOfRib(BGP_AFI.IPV4, BGP_SAFI.UNICAST);
    expect(isEndOfRib(ipv4Eor)).toEqual({ afi: 1, safi: 1 });
    const ipv4Bytes = assertLosslessRoundTrip(ipv4Eor, { fourOctetAs: true });
    expect(toHexString(ipv4Bytes)).toBe(hex(`${MARKER_HEX} 00 17 02 00 00 00 00`));

    // IPv6 unicast EoR: 19B header + 2B withdrawn=0 + 2B pathAttr=6 + MP_UNREACH(80 0f 03 00 02 01) = 29B (0x001d)
    const ipv6Eor = createEndOfRib(BGP_AFI.IPV6, BGP_SAFI.UNICAST);
    expect(isEndOfRib(ipv6Eor)).toEqual({ afi: 2, safi: 1 });
    const ipv6Bytes = assertLosslessRoundTrip(ipv6Eor, { fourOctetAs: true });
    expect(toHexString(ipv6Bytes)).toBe(
      hex(`${MARKER_HEX} 00 1d 02 00 00 00 06 80 0f 03 00 02 01`),
    );
  });

  it('encodes and decodes NOTIFICATION Hold Timer Expired (4/0) and Cease Administrative Shutdown (6/2)', () => {
    // 19B header + 1B code + 1B subcode = 21B (0x0015)
    const holdExpired: BgpNotificationMessage = {
      type: 'notification',
      errorCode: 4,
      errorSubcode: 0,
      dataHex: '',
    };
    const holdBytes = assertLosslessRoundTrip(holdExpired, { fourOctetAs: true });
    expect(toHexString(holdBytes)).toBe(hex(`${MARKER_HEX} 00 15 03 04 00`));

    const adminShutdown: BgpNotificationMessage = {
      type: 'notification',
      errorCode: 6,
      errorSubcode: 2,
      dataHex: '',
    };
    const ceaseBytes = assertLosslessRoundTrip(adminShutdown, { fourOctetAs: true });
    expect(toHexString(ceaseBytes)).toBe(hex(`${MARKER_HEX} 00 15 03 06 02`));

    // Cease with diagnostic Data bytes (21 + 2 = 23B = 0x0017)
    const withData: BgpNotificationMessage = {
      type: 'notification',
      errorCode: 7,
      errorSubcode: 1,
      dataHex: '00 18',
    };
    const dataBytes = assertLosslessRoundTrip(withData, { fourOctetAs: true });
    expect(toHexString(dataBytes)).toBe(hex(`${MARKER_HEX} 00 17 03 07 01 00 18`));
  });

  it('handles IPv4 and IPv6 prefix encoding boundaries accurately', () => {
    const ipv4Cases: readonly [string, number, string][] = [
      ['0.0.0.0/0', 0, ''],
      ['128.0.0.0/1', 1, '80'],
      ['10.0.0.0/8', 1, '0a'],
      ['10.128.0.0/9', 2, '0a80'],
      ['203.0.113.0/24', 3, 'cb0071'],
      ['203.0.113.128/25', 4, 'cb007180'],
      ['192.0.2.42/32', 4, 'c000022a'],
    ];

    for (const [cidr, expectedOctets, expectedHex] of ipv4Cases) {
      const parsed = parseCidrPrefix(cidr, BGP_AFI.IPV4);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        expect(parsed.value.encodedOctets.length).toBe(expectedOctets);
        expect(toHexString(parsed.value.encodedOctets)).toBe(expectedHex);
        expect(parsed.value.canonical).toBe(cidr);
      }
    }

    // Round-trip all IPv4 boundary prefixes in one UPDATE
    const v4BoundaryUpdate: BgpUpdateMessage = {
      type: 'update',
      withdrawnRoutes: ipv4Cases.map(([prefix]) => ({ prefix })),
      pathAttributes: [
        { kind: 'origin', origin: 0 },
        { kind: 'asPath', segments: [] },
        { kind: 'nextHop', nextHop: '192.0.2.1' },
      ],
      nlri: ipv4Cases.map(([prefix]) => ({ prefix })),
    };
    assertLosslessRoundTrip(v4BoundaryUpdate, { fourOctetAs: true });

    const ipv6Cases: readonly [string, number, string][] = [
      ['::/0', 0, ''],
      ['2001:db8:abcd::/48', 6, '20010db8abcd'],
      ['2001:db8:abcd:1234::/64', 8, '20010db8abcd1234'],
      ['2001:db8::1/128', 16, '20010db8000000000000000000000001'],
    ];

    for (const [cidr, expectedOctets, expectedHex] of ipv6Cases) {
      const parsed = parseCidrPrefix(cidr, BGP_AFI.IPV6);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        expect(parsed.value.encodedOctets.length).toBe(expectedOctets);
        expect(toHexString(parsed.value.encodedOctets)).toBe(expectedHex);
        expect(parsed.value.canonical).toBe(cidr);
      }
    }

    const v6BoundaryUpdate: BgpUpdateMessage = {
      type: 'update',
      withdrawnRoutes: [],
      pathAttributes: [
        {
          kind: 'mpReachNlri',
          afi: BGP_AFI.IPV6,
          safi: BGP_SAFI.UNICAST,
          nextHops: ['2001:db8::1', 'fe80::1'],
          nlri: ipv6Cases.map(([prefix]) => ({ prefix })),
        },
      ],
      nlri: [],
    };
    assertLosslessRoundTrip(v6BoundaryUpdate, { fourOctetAs: true });
  });

  it('supports Graceful Restart, ADD-PATH, Enhanced Route Refresh, Raw capabilities/attributes, AS4, Large Communities, and Extended Length', () => {
    const richOpen: BgpOpenMessage = {
      type: 'open',
      version: 4,
      asn: 65001,
      holdTime: 180,
      bgpIdentifier: '198.51.100.1',
      capabilities: [
        {
          kind: 'gracefulRestart',
          restartFlags: 0x8,
          restartTime: 120,
          tuples: [
            { afi: BGP_AFI.IPV4, safi: BGP_SAFI.UNICAST, forwardingState: true },
            { afi: BGP_AFI.IPV6, safi: BGP_SAFI.UNICAST, forwardingState: false },
          ],
        },
        {
          kind: 'addPath',
          entries: [{ afi: BGP_AFI.IPV4, safi: BGP_SAFI.UNICAST, sendReceive: 3 }],
        },
        { kind: 'enhancedRouteRefresh' },
        { kind: 'raw', code: 128, dataHex: 'de ad be ef' },
      ],
    };
    assertLosslessRoundTrip(richOpen, { fourOctetAs: true });

    // Extended Length attribute (> 255 bytes auto) + Raw attribute + AS4 + Large Community + ADD-PATH
    const bigRawData = 'ab'.repeat(260);
    const richUpdate: BgpUpdateMessage = {
      type: 'update',
      withdrawnRoutes: [{ prefix: '198.51.100.0/24', pathId: 7 }],
      pathAttributes: [
        { kind: 'origin', origin: 2 },
        {
          kind: 'asPath',
          segments: [
            { type: 2, asns: [65001, BGP_AS_TRANS] },
            { type: 1, asns: [65002, 65003] },
          ],
        },
        { kind: 'nextHop', nextHop: '192.0.2.2' },
        { kind: 'localPref', localPref: 200 },
        { kind: 'atomicAggregate' },
        { kind: 'aggregator', asn: 65001, ipAddress: '192.0.2.99' },
        {
          kind: 'communities',
          communities: [
            WELL_KNOWN_COMMUNITIES.NO_EXPORT,
            WELL_KNOWN_COMMUNITIES.BLACKHOLE,
            makeCommunity(65001, 200),
          ],
        },
        { kind: 'as4Path', segments: [{ type: 2, asns: [4200000001] }] },
        { kind: 'as4Aggregator', asn: 4200000001, ipAddress: '192.0.2.99' },
        {
          kind: 'largeCommunities',
          communities: [{ globalAdmin: 4200000001, localData1: 100, localData2: 200 }],
        },
        {
          kind: 'raw',
          typeCode: 200,
          flags: { optional: true, transitive: true, partial: true },
          dataHex: bigRawData,
        },
      ],
      nlri: [{ prefix: '203.0.113.0/24', pathId: 42 }],
    };

    const addPathCtx: BgpCodecContext = {
      fourOctetAs: false,
      addPath: new Set([afiSafiKey(BGP_AFI.IPV4, BGP_SAFI.UNICAST)]),
    };
    const encodedRich = assertLosslessRoundTrip(richUpdate, addPathCtx);
    // Verify Extended Length bit (0x10) was automatically set on the 260-byte raw attribute
    const decodedRich = decodeBgpMessages(encodedRich, addPathCtx);
    const rawAttr =
      decodedRich.messages[0].message.type === 'update'
        ? decodedRich.messages[0].message.pathAttributes.find((a) => a.kind === 'raw')
        : undefined;
    expect(rawAttr?.kind).toBe('raw');
    if (rawAttr?.kind === 'raw') {
      expect(rawAttr.dataHex).toBe(bigRawData);
      expect(rawAttr.flags?.partial).toBe(true);
    }

    // Well-known community display names
    expect(formatCommunity(WELL_KNOWN_COMMUNITIES.NO_EXPORT)).toContain('NO_EXPORT');
    expect(formatCommunity(WELL_KNOWN_COMMUNITIES.BLACKHOLE)).toContain('BLACKHOLE');
    expect(formatCommunity(makeCommunity(65001, 100))).toBe('65001:100');

    // ROUTE-REFRESH (Normal + BoRR + EoRR)
    const rrNormal: BgpRouteRefreshMessage = {
      type: 'routeRefresh',
      afi: BGP_AFI.IPV4,
      subtype: 0,
      safi: BGP_SAFI.UNICAST,
    };
    const rrBytes = assertLosslessRoundTrip(rrNormal, { fourOctetAs: true });
    expect(toHexString(rrBytes)).toBe(hex(`${MARKER_HEX} 00 17 05 00 01 00 01`));

    const rrBorr: BgpRouteRefreshMessage = {
      type: 'routeRefresh',
      afi: BGP_AFI.IPV6,
      subtype: 1,
      safi: BGP_SAFI.UNICAST,
    };
    assertLosslessRoundTrip(rrBorr, { fourOctetAs: true });
  });

  it('round-trips several concatenated BGP messages back to back and supports hex dump input', () => {
    const stream: readonly BgpMessage[] = [
      {
        type: 'open',
        version: 4,
        asn: 65001,
        holdTime: 90,
        bgpIdentifier: '192.0.2.1',
        capabilities: [{ kind: 'fourOctetAs', asn: 65001 }],
      },
      { type: 'keepalive' },
      createEndOfRib(BGP_AFI.IPV4, BGP_SAFI.UNICAST),
      { type: 'notification', errorCode: 6, errorSubcode: 2, dataHex: '' },
    ];

    const encoded = encodeBgpMessages(stream, { fourOctetAs: true });
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;

    const decoded = decodeBgpMessages(encoded.value, { fourOctetAs: true });
    expect(decoded.messages).toHaveLength(4);
    expect(decoded.unparsedBytes.length).toBe(0);
    expect(decoded.notes).toEqual([]);
    expect(decoded.messages.map((m) => m.message.type)).toEqual([
      'open',
      'keepalive',
      'update',
      'notification',
    ]);

    for (const item of decoded.messages) {
      assertValidDissectionTree(item.tree, item.bytes.length);
    }

    const viaHex = decodeBgpHex(toHexString(encoded.value), { fourOctetAs: true });
    expect(viaHex.messages).toHaveLength(4);
    expect(viaHex.unparsedBytes.length).toBe(0);
  });

  it('never throws on malformed or truncated input and preserves partial results + unparsed bytes', () => {
    // 1. Valid KEEPALIVE followed by truncated 5-byte tail
    const keepalive = encodeBgpMessage({ type: 'keepalive' });
    expect(keepalive.ok).toBe(true);
    if (!keepalive.ok) return;

    const withTail = new Uint8Array(keepalive.value.bytes.length + 5);
    withTail.set(keepalive.value.bytes, 0);
    withTail.set([0xff, 0xff, 0x00, 0x10, 0x02], keepalive.value.bytes.length);

    const partial = decodeBgpMessages(withTail);
    expect(partial.messages).toHaveLength(1);
    expect(partial.messages[0].message.type).toBe('keepalive');
    expect(partial.unparsedBytes.length).toBe(5);
    expect(partial.unparsedOffset).toBe(19);
    expect(partial.notes.length).toBeGreaterThan(0);

    // 2. Declared length < 19
    const badLen = parseHexBytes(`${MARKER_HEX} 00 0a 04`);
    expect(badLen.ok).toBe(true);
    if (badLen.ok) {
      const res = decodeBgpMessages(badLen.value);
      expect(res.messages).toHaveLength(0);
      expect(res.unparsedBytes.length).toBe(19);
      expect(res.notes.length).toBeGreaterThan(0);
    }

    // 3. Complete UPDATE frame containing a truncated path attribute inside
    const badAttrUpdate = parseHexBytes(`${MARKER_HEX} 00 1c 02 00 00 00 05 40 01 10 aa bb`);
    expect(badAttrUpdate.ok).toBe(true);
    if (badAttrUpdate.ok) {
      const res = decodeBgpMessages(badAttrUpdate.value);
      expect(res.messages).toHaveLength(1);
      expect(res.notes.length).toBeGreaterThan(0);
      assertValidDissectionTree(res.messages[0].tree, badAttrUpdate.value.length);
    }

    // 4. Invalid hex text
    const badHex = decodeBgpHex('not-valid-hex!!');
    expect(badHex.messages).toHaveLength(0);
    expect(badHex.notes.length).toBeGreaterThan(0);
  });

  it('has zero dependency on src/core/layers/ or src/ui/', () => {
    const files = readdirSync(THIS_DIR).filter(
      (f) => f.endsWith('.ts') && !f.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const src = readFileSync(join(THIS_DIR, file), 'utf8');
      expect(src, `${file} must not import from layers/`).not.toMatch(/from\s+['"][^'"]*layers/);
      expect(src, `${file} must not import from ui/`).not.toMatch(/from\s+['"][^'"]*ui/);
    }
  });
});
