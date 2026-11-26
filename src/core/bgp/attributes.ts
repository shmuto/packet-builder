import {
  formatIPv4,
  formatIPv6,
  parseHexBytes,
  parseIPv4,
  parseIPv6,
  readUint16BE,
  readUint32BE,
  toHexString,
  writeUint16BE,
  writeUint32BE,
} from '../bytes';
import { err, ok, type Result } from '../result';
import { decodePrefixList, encodePrefixList } from './prefix';
import {
  formatAfiSafi,
  formatCommunity,
  getAsPathSegmentTypeName,
  getAttrSpec,
  getCommunityInfo,
  getOriginName,
} from './tables';
import {
  BGP_AFI,
  BGP_AS_TRANS,
  BGP_ATTR_TYPE,
  hasAddPathForAfiSafi,
  type BgpAsPathSegment,
  type BgpAsPathSegmentType,
  type BgpAttrFlags,
  type BgpAttrFlagsOverride,
  type BgpCodecContext,
  type BgpLargeCommunity,
  type BgpPathAttribute,
  type DissectionNode,
} from './types';

function isUint8(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xff;
}

function isUint16(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xffff;
}

function isUint32(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

function getAttrTypeCode(attr: BgpPathAttribute): number {
  switch (attr.kind) {
    case 'origin':
      return BGP_ATTR_TYPE.ORIGIN;
    case 'asPath':
      return BGP_ATTR_TYPE.AS_PATH;
    case 'nextHop':
      return BGP_ATTR_TYPE.NEXT_HOP;
    case 'med':
      return BGP_ATTR_TYPE.MULTI_EXIT_DISC;
    case 'localPref':
      return BGP_ATTR_TYPE.LOCAL_PREF;
    case 'atomicAggregate':
      return BGP_ATTR_TYPE.ATOMIC_AGGREGATE;
    case 'aggregator':
      return BGP_ATTR_TYPE.AGGREGATOR;
    case 'communities':
      return BGP_ATTR_TYPE.COMMUNITIES;
    case 'mpReachNlri':
      return BGP_ATTR_TYPE.MP_REACH_NLRI;
    case 'mpUnreachNlri':
      return BGP_ATTR_TYPE.MP_UNREACH_NLRI;
    case 'as4Path':
      return BGP_ATTR_TYPE.AS4_PATH;
    case 'as4Aggregator':
      return BGP_ATTR_TYPE.AS4_AGGREGATOR;
    case 'largeCommunities':
      return BGP_ATTR_TYPE.LARGE_COMMUNITY;
    case 'raw':
      return attr.typeCode;
  }
}

export function resolveAttrFlags(
  typeCode: number,
  valueLength: number,
  override?: BgpAttrFlagsOverride,
): { readonly flags: BgpAttrFlags; readonly unusedBits: number; readonly byte: number } {
  const defaults = getAttrSpec(typeCode).defaultFlags;
  const optional = override?.optional ?? defaults.optional;
  const transitive = override?.transitive ?? defaults.transitive;
  const partial = override?.partial ?? defaults.partial;
  const extendedLength = override?.extendedLength ?? valueLength > 255;
  const unusedBits = (override?.unusedBits ?? 0) & 0x0f;
  const byte =
    (optional ? 0x80 : 0) |
    (transitive ? 0x40 : 0) |
    (partial ? 0x20 : 0) |
    (extendedLength ? 0x10 : 0) |
    unusedBits;
  return {
    flags: { optional, transitive, partial, extendedLength },
    unusedBits,
    byte,
  };
}

function formatAttrFlags(flags: BgpAttrFlags, byte: number): string {
  const names: string[] = [];
  names.push(flags.optional ? 'Optional' : 'Well-known');
  names.push(flags.transitive ? 'Transitive' : 'Non-transitive');
  if (flags.partial) names.push('Partial');
  if (flags.extendedLength) names.push('Extended-Length');
  return `0x${byte.toString(16).padStart(2, '0')} (${names.join(', ')})`;
}

function formatAsPathSummary(segments: readonly BgpAsPathSegment[]): string {
  if (segments.length === 0) return '(empty)';
  return segments
    .map((seg) =>
      seg.type === 1
        ? `{${seg.asns.join(', ')}}`
        : seg.asns.join(' '),
    )
    .join(' ');
}

function encodeAsPathSegments(
  segments: readonly BgpAsPathSegment[],
  asWidth: 2 | 4,
  valueStart: number,
  idPrefix: string,
  reference: string,
): Result<{ readonly bytes: Uint8Array; readonly nodes: readonly DissectionNode[] }> {
  const chunks: Uint8Array[] = [];
  const nodes: DissectionNode[] = [];
  let cursor = valueStart;

  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg.type !== 1 && seg.type !== 2) {
      return err(`AS path segment #${i + 1} has invalid type ${seg.type} (expected 1=AS_SET or 2=AS_SEQUENCE).`);
    }
    if (seg.asns.length > 255) {
      return err(`AS path segment #${i + 1} exceeds 255 ASNs (${seg.asns.length}).`);
    }
    const maxAs = asWidth === 4 ? 0xffffffff : 0xffff;
    const segLen = 2 + seg.asns.length * asWidth;
    const buf = new Uint8Array(segLen);
    buf[0] = seg.type;
    buf[1] = seg.asns.length;

    const segChildren: DissectionNode[] = [
      {
        id: `${idPrefix}.seg[${i}].type`,
        label: 'Segment Type',
        value: `${seg.type} (${getAsPathSegmentTypeName(seg.type)})`,
        explanation:
          seg.type === 2
            ? 'AS_SEQUENCE (2): ordered list of ASNs the route traversed, most recent first.'
            : 'AS_SET (1): unordered set of ASNs created when aggregating routes from multiple paths.',
        reference,
        byteRange: { start: cursor, end: cursor + 1 },
      },
      {
        id: `${idPrefix}.seg[${i}].count`,
        label: 'Segment Length (ASN Count)',
        value: `${seg.asns.length} ${seg.asns.length === 1 ? 'AS' : 'ASes'}`,
        explanation: `Number of ${asWidth}-byte AS numbers in this segment (counts ASNs, not octets).`,
        reference,
        byteRange: { start: cursor + 1, end: cursor + 2 },
      },
    ];

    for (let j = 0; j < seg.asns.length; j++) {
      const asn = seg.asns[j];
      if (!Number.isInteger(asn) || asn < 0 || asn > maxAs) {
        return err(
          `AS path segment #${i + 1} ASN #${j + 1} (${asn}) out of range for ${asWidth}-byte AS encoding (0-${maxAs}).`,
        );
      }
      const off = 2 + j * asWidth;
      if (asWidth === 4) {
        writeUint32BE(buf, off, asn);
      } else {
        writeUint16BE(buf, off, asn);
      }
      const absOff = cursor + off;
      segChildren.push({
        id: `${idPrefix}.seg[${i}].asn[${j}]`,
        label: `AS #${j + 1}`,
        value: asn === BGP_AS_TRANS ? `${asn} (AS_TRANS)` : String(asn),
        explanation:
          asn === BGP_AS_TRANS
            ? 'AS_TRANS (23456) placeholder standing in for a 4-octet ASN across a 2-octet BGP peer; look in AS4_PATH for the real ASN.'
            : `${asWidth}-octet Autonomous System Number in the route’s path.`,
        reference: asn === BGP_AS_TRANS ? 'RFC 6793 §4.2.2' : reference,
        byteRange: { start: absOff, end: absOff + asWidth },
      });
    }

    nodes.push({
      id: `${idPrefix}.seg[${i}]`,
      label: `Segment #${i + 1}: ${getAsPathSegmentTypeName(seg.type)}`,
      value: seg.type === 1 ? `{${seg.asns.join(', ')}}` : seg.asns.join(' '),
      explanation: `AS path segment encoded with ${asWidth}-byte AS numbers.`,
      reference,
      byteRange: { start: cursor, end: cursor + segLen },
      children: segChildren,
    });

    chunks.push(buf);
    cursor += segLen;
  }

  const total = cursor - valueStart;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const chunk of chunks) {
    out.set(chunk, pos);
    pos += chunk.length;
  }
  return ok({ bytes: out, nodes });
}

export interface EncodedPathAttribute {
  readonly bytes: Uint8Array;
  readonly node: DissectionNode;
}

export function encodePathAttribute(
  attr: BgpPathAttribute,
  ctx: BgpCodecContext,
  baseOffset: number,
  idPrefix: string,
): Result<EncodedPathAttribute> {
  const typeCode = getAttrTypeCode(attr);
  if (!isUint8(typeCode)) {
    return err(`Attribute type code must be 0-255 (got ${typeCode}).`);
  }

  // First pass: determine value bytes and summary, then compute header length (3B vs 4B)
  // so child byteRanges use the exact valueStart offset!
  const buildValue = (
    valueStart: number,
  ): Result<{ readonly valueBytes: Uint8Array; readonly summary: string; readonly children: readonly DissectionNode[] }> => {
    switch (attr.kind) {
      case 'origin': {
        if (attr.origin !== 0 && attr.origin !== 1 && attr.origin !== 2) {
          return err(`Invalid ORIGIN value ${attr.origin} (expected 0=IGP, 1=EGP, 2=INCOMPLETE).`);
        }
        const valueBytes = new Uint8Array([attr.origin]);
        const name = getOriginName(attr.origin);
        return ok({
          valueBytes,
          summary: `${name} (${attr.origin})`,
          children: [
            {
              id: `${idPrefix}.origin`,
              label: 'Origin',
              value: `${name} (${attr.origin})`,
              explanation:
                attr.origin === 0
                  ? 'IGP (0): route originated inside the origin AS (e.g., via network statement).'
                  : attr.origin === 1
                    ? 'EGP (1): route learned via the legacy Exterior Gateway Protocol.'
                    : 'INCOMPLETE (2): route originated by other means (typically redistribution).',
              reference: 'RFC 4271 §5.1.1',
              byteRange: { start: valueStart, end: valueStart + 1 },
            },
          ],
        });
      }

      case 'asPath': {
        const asWidth: 2 | 4 = ctx.fourOctetAs ? 4 : 2;
        const ref = ctx.fourOctetAs ? 'RFC 4271 §5.1.2 / RFC 6793 §4.1' : 'RFC 4271 §5.1.2';
        const encoded = encodeAsPathSegments(attr.segments, asWidth, valueStart, idPrefix, ref);
        if (!encoded.ok) return encoded;
        return ok({
          valueBytes: encoded.value.bytes,
          summary: `${formatAsPathSummary(attr.segments)} (${asWidth}-byte AS)`,
          children: encoded.value.nodes,
        });
      }

      case 'nextHop': {
        const parsed = parseIPv4(attr.nextHop);
        if (!parsed.ok) return err(`NEXT_HOP invalid IPv4: ${parsed.error}`);
        return ok({
          valueBytes: parsed.value,
          summary: attr.nextHop,
          children: [
            {
              id: `${idPrefix}.nextHop`,
              label: 'Next Hop',
              value: attr.nextHop,
              explanation: 'IPv4 address of the border router to forward packets toward the IPv4 NLRI in this UPDATE.',
              reference: 'RFC 4271 §5.1.3',
              byteRange: { start: valueStart, end: valueStart + 4 },
            },
          ],
        });
      }

      case 'med': {
        if (!isUint32(attr.med)) {
          return err(`MULTI_EXIT_DISC must be a 32-bit unsigned integer (got ${attr.med}).`);
        }
        const buf = new Uint8Array(4);
        writeUint32BE(buf, 0, attr.med);
        return ok({
          valueBytes: buf,
          summary: String(attr.med),
          children: [
            {
              id: `${idPrefix}.med`,
              label: 'MED Value',
              value: String(attr.med),
              explanation: '32-bit metric suggesting preferred entry point to a neighboring AS (lower is preferred).',
              reference: 'RFC 4271 §5.1.4',
              byteRange: { start: valueStart, end: valueStart + 4 },
            },
          ],
        });
      }

      case 'localPref': {
        if (!isUint32(attr.localPref)) {
          return err(`LOCAL_PREF must be a 32-bit unsigned integer (got ${attr.localPref}).`);
        }
        const buf = new Uint8Array(4);
        writeUint32BE(buf, 0, attr.localPref);
        return ok({
          valueBytes: buf,
          summary: String(attr.localPref),
          children: [
            {
              id: `${idPrefix}.localPref`,
              label: 'Local Preference',
              value: String(attr.localPref),
              explanation: '32-bit intra-AS preference shared across iBGP peers (higher is preferred; default is commonly 100).',
              reference: 'RFC 4271 §5.1.5',
              byteRange: { start: valueStart, end: valueStart + 4 },
            },
          ],
        });
      }

      case 'atomicAggregate': {
        return ok({
          valueBytes: new Uint8Array(0),
          summary: 'Present (length 0)',
          children: [],
        });
      }

      case 'aggregator': {
        const asWidth: 2 | 4 = ctx.fourOctetAs ? 4 : 2;
        const maxAs = asWidth === 4 ? 0xffffffff : 0xffff;
        if (!Number.isInteger(attr.asn) || attr.asn < 0 || attr.asn > maxAs) {
          return err(`AGGREGATOR ASN ${attr.asn} out of range for ${asWidth}-byte AS encoding.`);
        }
        const ipRes = parseIPv4(attr.ipAddress);
        if (!ipRes.ok) return err(`AGGREGATOR IP invalid: ${ipRes.error}`);
        const buf = new Uint8Array(asWidth + 4);
        if (asWidth === 4) {
          writeUint32BE(buf, 0, attr.asn);
        } else {
          writeUint16BE(buf, 0, attr.asn);
        }
        buf.set(ipRes.value, asWidth);
        const ref = ctx.fourOctetAs ? 'RFC 4271 §5.1.7 / RFC 6793 §4.1' : 'RFC 4271 §5.1.7';
        return ok({
          valueBytes: buf,
          summary: `AS ${attr.asn}, Router ${attr.ipAddress}`,
          children: [
            {
              id: `${idPrefix}.asn`,
              label: 'Aggregator AS',
              value: String(attr.asn),
              explanation: `${asWidth}-octet ASN of the speaker that formed the aggregate route.`,
              reference: ref,
              byteRange: { start: valueStart, end: valueStart + asWidth },
            },
            {
              id: `${idPrefix}.ip`,
              label: 'Aggregator Origin IP',
              value: attr.ipAddress,
              explanation: 'IPv4 BGP Identifier of the router that performed the aggregation.',
              reference: 'RFC 4271 §5.1.7',
              byteRange: { start: valueStart + asWidth, end: valueStart + asWidth + 4 },
            },
          ],
        });
      }

      case 'communities': {
        const buf = new Uint8Array(attr.communities.length * 4);
        const children: DissectionNode[] = [];
        for (let i = 0; i < attr.communities.length; i++) {
          const val = attr.communities[i];
          if (!isUint32(val)) {
            return err(`Community #${i + 1} must be a 32-bit unsigned integer (got ${val}).`);
          }
          writeUint32BE(buf, i * 4, val);
          const info = getCommunityInfo(val);
          children.push({
            id: `${idPrefix}.community[${i}]`,
            label: `Community #${i + 1}`,
            value: formatCommunity(val),
            explanation: info.explanation,
            reference: info.reference,
            byteRange: { start: valueStart + i * 4, end: valueStart + i * 4 + 4 },
          });
        }
        return ok({
          valueBytes: buf,
          summary:
            attr.communities.length === 0
              ? '(none)'
              : attr.communities.map((c) => formatCommunity(c)).join(', '),
          children,
        });
      }

      case 'mpReachNlri': {
        if (!isUint16(attr.afi) || !isUint8(attr.safi)) {
          return err(`MP_REACH_NLRI invalid AFI/SAFI (${attr.afi}/${attr.safi}).`);
        }
        const reserved = attr.reserved ?? 0;
        if (!isUint8(reserved)) {
          return err(`MP_REACH_NLRI reserved byte must be 0-255 (got ${reserved}).`);
        }

        let nhBytes: Uint8Array;
        let nhDisplay: string;
        if (attr.nextHopRawHex !== undefined) {
          const rawNh = parseHexBytes(attr.nextHopRawHex);
          if (!rawNh.ok) return err(`MP_REACH_NLRI nextHopRawHex error: ${rawNh.error}`);
          nhBytes = rawNh.value;
          nhDisplay = `0x${toHexString(nhBytes)}`;
        } else if (attr.afi === BGP_AFI.IPV6) {
          const parts: Uint8Array[] = [];
          for (const nh of attr.nextHops) {
            const parsed = parseIPv6(nh);
            if (!parsed.ok) return err(`MP_REACH_NLRI IPv6 next hop "${nh}": ${parsed.error}`);
            parts.push(parsed.value);
          }
          nhBytes = new Uint8Array(parts.length * 16);
          parts.forEach((p, idx) => nhBytes.set(p, idx * 16));
          nhDisplay = attr.nextHops.join(', ') || '(none)';
        } else if (attr.afi === BGP_AFI.IPV4) {
          const parts: Uint8Array[] = [];
          for (const nh of attr.nextHops) {
            const parsed = parseIPv4(nh);
            if (!parsed.ok) return err(`MP_REACH_NLRI IPv4 next hop "${nh}": ${parsed.error}`);
            parts.push(parsed.value);
          }
          nhBytes = new Uint8Array(parts.length * 4);
          parts.forEach((p, idx) => nhBytes.set(p, idx * 4));
          nhDisplay = attr.nextHops.join(', ') || '(none)';
        } else {
          nhBytes = new Uint8Array(0);
          nhDisplay = '(none)';
        }

        if (nhBytes.length > 255) {
          return err(`MP_REACH_NLRI next hop exceeds 255 bytes (${nhBytes.length}).`);
        }

        const nlriStart = valueStart + 4 + nhBytes.length + 1;
        const addPath = hasAddPathForAfiSafi(ctx, attr.afi, attr.safi);
        let nlriBytes: Uint8Array;
        let nlriNodes: readonly DissectionNode[];

        if (attr.afi === BGP_AFI.IPV4 || attr.afi === BGP_AFI.IPV6) {
          const encodedNlri = encodePrefixList(
            attr.nlri,
            attr.afi,
            addPath,
            nlriStart,
            `${idPrefix}.nlri`,
            'Reachable MP-BGP route prefix',
          );
          if (!encodedNlri.ok) return encodedNlri;
          nlriBytes = encodedNlri.value.bytes;
          nlriNodes = encodedNlri.value.nodes;
        } else {
          nlriBytes = new Uint8Array(0);
          nlriNodes = [];
        }

        const totalLen = 4 + nhBytes.length + 1 + nlriBytes.length;
        const buf = new Uint8Array(totalLen);
        writeUint16BE(buf, 0, attr.afi);
        buf[2] = attr.safi;
        buf[3] = nhBytes.length;
        buf.set(nhBytes, 4);
        buf[4 + nhBytes.length] = reserved;
        buf.set(nlriBytes, 5 + nhBytes.length);

        const children: DissectionNode[] = [
          {
            id: `${idPrefix}.afi`,
            label: 'AFI',
            value: `${attr.afi} (${formatAfiSafi(attr.afi, attr.safi).split(' ')[0]})`,
            explanation: 'Address Family Identifier for the reachable routes carried in this attribute.',
            reference: 'RFC 4760 §3',
            byteRange: { start: valueStart, end: valueStart + 2 },
          },
          {
            id: `${idPrefix}.safi`,
            label: 'SAFI',
            value: String(attr.safi),
            explanation: 'Subsequent Address Family Identifier (1 = Unicast).',
            reference: 'RFC 4760 §3',
            byteRange: { start: valueStart + 2, end: valueStart + 3 },
          },
          {
            id: `${idPrefix}.nhLen`,
            label: 'Next Hop Network Address Length',
            value: `${nhBytes.length} bytes`,
            explanation:
              'Length of the Next Hop address field (16 bytes for one IPv6 global address, or 32 bytes for global + link-local per RFC 2545 §3).',
            reference: 'RFC 4760 §3',
            byteRange: { start: valueStart + 3, end: valueStart + 4 },
          },
        ];

        if (nhBytes.length > 0) {
          children.push({
            id: `${idPrefix}.nextHop`,
            label: 'Network Address of Next Hop',
            value: nhDisplay,
            explanation: 'Next-hop router address(es) used to reach the MP-BGP prefixes announced below.',
            reference: attr.afi === BGP_AFI.IPV6 ? 'RFC 2545 §3 / RFC 4760 §3' : 'RFC 4760 §3',
            byteRange: { start: valueStart + 4, end: valueStart + 4 + nhBytes.length },
          });
        }

        children.push({
          id: `${idPrefix}.reserved`,
          label: 'Reserved',
          value: `0x${reserved.toString(16).padStart(2, '0')}`,
          explanation: 'Reserved octet set to 0 by the sender (historically Number of SNPAs in RFC 2858).',
          reference: 'RFC 4760 §3',
          byteRange: { start: valueStart + 4 + nhBytes.length, end: nlriStart },
        });

        if (nlriBytes.length > 0) {
          children.push({
            id: `${idPrefix}.nlri`,
            label: 'Network Layer Reachability Information',
            value: attr.nlri.map((p) => p.prefix).join(', '),
            explanation: 'Prefixes being advertised as reachable for this AFI/SAFI.',
            reference: 'RFC 4760 §3',
            byteRange: { start: nlriStart, end: nlriStart + nlriBytes.length },
            children: nlriNodes,
          });
        }

        return ok({
          valueBytes: buf,
          summary: `${formatAfiSafi(attr.afi, attr.safi)}, Next Hop ${nhDisplay}, ${attr.nlri.length} ${attr.nlri.length === 1 ? 'prefix' : 'prefixes'}`,
          children,
        });
      }

      case 'mpUnreachNlri': {
        if (!isUint16(attr.afi) || !isUint8(attr.safi)) {
          return err(`MP_UNREACH_NLRI invalid AFI/SAFI (${attr.afi}/${attr.safi}).`);
        }
        const withdrawnStart = valueStart + 3;
        const addPath = hasAddPathForAfiSafi(ctx, attr.afi, attr.safi);
        let withdrawnBytes: Uint8Array;
        let withdrawnNodes: readonly DissectionNode[];

        if (attr.afi === BGP_AFI.IPV4 || attr.afi === BGP_AFI.IPV6) {
          const encoded = encodePrefixList(
            attr.withdrawnRoutes,
            attr.afi,
            addPath,
            withdrawnStart,
            `${idPrefix}.withdrawn`,
            'Withdrawn MP-BGP route prefix',
          );
          if (!encoded.ok) return encoded;
          withdrawnBytes = encoded.value.bytes;
          withdrawnNodes = encoded.value.nodes;
        } else {
          withdrawnBytes = new Uint8Array(0);
          withdrawnNodes = [];
        }

        const buf = new Uint8Array(3 + withdrawnBytes.length);
        writeUint16BE(buf, 0, attr.afi);
        buf[2] = attr.safi;
        buf.set(withdrawnBytes, 3);

        const children: DissectionNode[] = [
          {
            id: `${idPrefix}.afi`,
            label: 'AFI',
            value: `${attr.afi} (${formatAfiSafi(attr.afi, attr.safi).split(' ')[0]})`,
            explanation: 'Address Family Identifier for the withdrawn routes (or End-of-RIB marker if empty).',
            reference: 'RFC 4760 §4',
            byteRange: { start: valueStart, end: valueStart + 2 },
          },
          {
            id: `${idPrefix}.safi`,
            label: 'SAFI',
            value: String(attr.safi),
            explanation: 'Subsequent Address Family Identifier (1 = Unicast).',
            reference: 'RFC 4760 §4',
            byteRange: { start: valueStart + 2, end: valueStart + 3 },
          },
        ];

        if (withdrawnBytes.length > 0) {
          children.push({
            id: `${idPrefix}.withdrawn`,
            label: 'Withdrawn Routes',
            value: attr.withdrawnRoutes.map((p) => p.prefix).join(', '),
            explanation: 'Prefixes being withdrawn from reachability for this AFI/SAFI.',
            reference: 'RFC 4760 §4',
            byteRange: { start: withdrawnStart, end: withdrawnStart + withdrawnBytes.length },
            children: withdrawnNodes,
          });
        }

        const isEor = attr.withdrawnRoutes.length === 0;
        return ok({
          valueBytes: buf,
          summary: isEor
            ? `${formatAfiSafi(attr.afi, attr.safi)} — End-of-RIB (0 withdrawn)`
            : `${formatAfiSafi(attr.afi, attr.safi)}, ${attr.withdrawnRoutes.length} withdrawn`,
          children,
        });
      }

      case 'as4Path': {
        const encoded = encodeAsPathSegments(
          attr.segments,
          4,
          valueStart,
          idPrefix,
          'RFC 6793 §4.2.2',
        );
        if (!encoded.ok) return encoded;
        return ok({
          valueBytes: encoded.value.bytes,
          summary: `${formatAsPathSummary(attr.segments)} (4-byte AS)`,
          children: encoded.value.nodes,
        });
      }

      case 'as4Aggregator': {
        if (!isUint32(attr.asn)) {
          return err(`AS4_AGGREGATOR ASN must be a 32-bit unsigned integer (got ${attr.asn}).`);
        }
        const ipRes = parseIPv4(attr.ipAddress);
        if (!ipRes.ok) return err(`AS4_AGGREGATOR IP invalid: ${ipRes.error}`);
        const buf = new Uint8Array(8);
        writeUint32BE(buf, 0, attr.asn);
        buf.set(ipRes.value, 4);
        return ok({
          valueBytes: buf,
          summary: `AS ${attr.asn}, Router ${attr.ipAddress}`,
          children: [
            {
              id: `${idPrefix}.asn`,
              label: 'AS4 Aggregator AS',
              value: String(attr.asn),
              explanation: '4-octet ASN of the aggregating router, preserved across 2-octet BGP speakers.',
              reference: 'RFC 6793 §4.2.2',
              byteRange: { start: valueStart, end: valueStart + 4 },
            },
            {
              id: `${idPrefix}.ip`,
              label: 'AS4 Aggregator Origin IP',
              value: attr.ipAddress,
              explanation: 'IPv4 BGP Identifier of the aggregating router.',
              reference: 'RFC 6793 §4.2.2',
              byteRange: { start: valueStart + 4, end: valueStart + 8 },
            },
          ],
        });
      }

      case 'largeCommunities': {
        const buf = new Uint8Array(attr.communities.length * 12);
        const children: DissectionNode[] = [];
        for (let i = 0; i < attr.communities.length; i++) {
          const lc = attr.communities[i];
          if (!isUint32(lc.globalAdmin) || !isUint32(lc.localData1) || !isUint32(lc.localData2)) {
            return err(`Large Community #${i + 1} values must be 32-bit unsigned integers.`);
          }
          const off = i * 12;
          writeUint32BE(buf, off, lc.globalAdmin);
          writeUint32BE(buf, off + 4, lc.localData1);
          writeUint32BE(buf, off + 8, lc.localData2);
          const absOff = valueStart + off;
          const formatted = `${lc.globalAdmin}:${lc.localData1}:${lc.localData2}`;
          children.push({
            id: `${idPrefix}.lc[${i}]`,
            label: `Large Community #${i + 1}`,
            value: formatted,
            explanation: '96-bit Large Community (Global Administrator : Local Data 1 : Local Data 2) supporting 32-bit ASNs.',
            reference: 'RFC 8092 §3',
            byteRange: { start: absOff, end: absOff + 12 },
            children: [
              {
                id: `${idPrefix}.lc[${i}].globalAdmin`,
                label: 'Global Administrator',
                value: String(lc.globalAdmin),
                explanation: 'Typically the 32-bit ASN of the network defining the meaning of this Large Community.',
                reference: 'RFC 8092 §3',
                byteRange: { start: absOff, end: absOff + 4 },
              },
              {
                id: `${idPrefix}.lc[${i}].localData1`,
                label: 'Local Data Part 1',
                value: String(lc.localData1),
                explanation: 'Operator-defined 32-bit action or category code.',
                reference: 'RFC 8092 §3',
                byteRange: { start: absOff + 4, end: absOff + 8 },
              },
              {
                id: `${idPrefix}.lc[${i}].localData2`,
                label: 'Local Data Part 2',
                value: String(lc.localData2),
                explanation: 'Operator-defined 32-bit parameter or target value.',
                reference: 'RFC 8092 §3',
                byteRange: { start: absOff + 8, end: absOff + 12 },
              },
            ],
          });
        }
        return ok({
          valueBytes: buf,
          summary:
            attr.communities.length === 0
              ? '(none)'
              : attr.communities
                  .map((lc) => `${lc.globalAdmin}:${lc.localData1}:${lc.localData2}`)
                  .join(', '),
          children,
        });
      }

      case 'raw': {
        const parsed = parseHexBytes(attr.dataHex);
        if (!parsed.ok) return err(`Raw attribute (type ${attr.typeCode}) dataHex: ${parsed.error}`);
        const valueBytes = parsed.value;
        return ok({
          valueBytes,
          summary: valueBytes.length === 0 ? '(empty)' : `0x${toHexString(valueBytes)}`,
          children:
            valueBytes.length > 0
              ? [
                  {
                    id: `${idPrefix}.data`,
                    label: 'Attribute Value (Raw)',
                    value: `0x${toHexString(valueBytes)} (${valueBytes.length} ${valueBytes.length === 1 ? 'byte' : 'bytes'})`,
                    explanation: 'Opaque path attribute value bytes.',
                    reference: 'RFC 4271 §4.3',
                    byteRange: { start: valueStart, end: valueStart + valueBytes.length },
                  },
                ]
              : [],
        });
      }
    }
  };

  // Probe value length first with placeholder offset 0 to know whether Extended Length (2B) is used
  const probe = buildValue(0);
  if (!probe.ok) return probe;

  const { flags, byte: flagsByte } = resolveAttrFlags(
    typeCode,
    probe.value.valueBytes.length,
    attr.flags,
  );
  const lengthFieldWidth = flags.extendedLength ? 2 : 1;
  const headerLen = 2 + lengthFieldWidth;
  const valueStart = baseOffset + headerLen;

  const finalVal = buildValue(valueStart);
  if (!finalVal.ok) return finalVal;
  const { valueBytes, summary, children: valueChildren } = finalVal.value;

  const wireLength = attr.lengthOverride ?? valueBytes.length;
  const maxWireLen = flags.extendedLength ? 0xffff : 0xff;
  if (!Number.isInteger(wireLength) || wireLength < 0 || wireLength > maxWireLen) {
    return err(
      `Attribute type ${typeCode} length ${wireLength} does not fit in ${lengthFieldWidth}-byte length field (0-${maxWireLen}).`,
    );
  }

  const out = new Uint8Array(headerLen + valueBytes.length);
  out[0] = flagsByte;
  out[1] = typeCode;
  if (flags.extendedLength) {
    writeUint16BE(out, 2, wireLength);
  } else {
    out[2] = wireLength;
  }
  out.set(valueBytes, headerLen);

  const spec = getAttrSpec(typeCode);
  const headerNodes: DissectionNode[] = [
    {
      id: `${idPrefix}.flags`,
      label: 'Attribute Flags',
      value: formatAttrFlags(flags, flagsByte),
      explanation:
        '4 flag bits control handling: Optional (bit 7), Transitive (bit 6), Partial (bit 5), and Extended Length (bit 4, 2-byte length when set).',
      reference: 'RFC 4271 §4.3',
      byteRange: { start: baseOffset, end: baseOffset + 1 },
    },
    {
      id: `${idPrefix}.typeCode`,
      label: 'Attribute Type Code',
      value: `${typeCode} (${spec.name})`,
      explanation: `1-byte IANA code identifying path attribute ${spec.name}.`,
      reference: spec.reference,
      byteRange: { start: baseOffset + 1, end: baseOffset + 2 },
    },
    {
      id: `${idPrefix}.length`,
      label: flags.extendedLength ? 'Attribute Length (Extended, 2B)' : 'Attribute Length (1B)',
      value:
        attr.lengthOverride !== undefined && attr.lengthOverride !== valueBytes.length
          ? `${wireLength} bytes (manual override; actual ${valueBytes.length} bytes)`
          : `${wireLength} ${wireLength === 1 ? 'byte' : 'bytes'}`,
      explanation: flags.extendedLength
        ? '2-byte attribute value length because the Extended Length flag is set (used automatically above 255 bytes).'
        : '1-byte attribute value length in octets.',
      reference: 'RFC 4271 §4.3',
      byteRange: { start: baseOffset + 2, end: valueStart },
    },
  ];

  const node: DissectionNode = {
    id: idPrefix,
    label: `Path Attribute: ${spec.name} (${typeCode})`,
    value: summary,
    explanation: spec.explanation,
    reference: spec.reference,
    byteRange: { start: baseOffset, end: baseOffset + out.length },
    children: [...headerNodes, ...valueChildren],
  };

  return ok({ bytes: out, node });
}

function decodeAsPathSegments(
  slice: Uint8Array,
  asWidth: 2 | 4,
): readonly BgpAsPathSegment[] | null {
  const segments: BgpAsPathSegment[] = [];
  let pos = 0;
  while (pos < slice.length) {
    if (pos + 2 > slice.length) return null;
    const segType = slice[pos];
    const count = slice[pos + 1];
    pos += 2;
    if (segType !== 1 && segType !== 2) return null;
    const needed = count * asWidth;
    if (pos + needed > slice.length) return null;
    const asns: number[] = [];
    for (let i = 0; i < count; i++) {
      asns.push(asWidth === 4 ? readUint32BE(slice, pos) : readUint16BE(slice, pos));
      pos += asWidth;
    }
    segments.push({ type: segType as BgpAsPathSegmentType, asns });
  }
  return segments;
}

function buildDecodedFlagsOverride(
  typeCode: number,
  valueLen: number,
  flagsByte: number,
): BgpAttrFlagsOverride | undefined {
  const defaults = resolveAttrFlags(typeCode, valueLen);
  if (defaults.byte === flagsByte) {
    return undefined;
  }
  const unusedBits = flagsByte & 0x0f;
  return {
    optional: (flagsByte & 0x80) !== 0,
    transitive: (flagsByte & 0x40) !== 0,
    partial: (flagsByte & 0x20) !== 0,
    extendedLength: (flagsByte & 0x10) !== 0,
    ...(unusedBits !== 0 ? { unusedBits } : {}),
  };
}

export interface DecodedPathAttributes {
  readonly attributes: readonly BgpPathAttribute[];
  readonly nodes: readonly DissectionNode[];
  readonly notes: readonly string[];
}

export function decodePathAttributesSlice(
  bytes: Uint8Array,
  start: number,
  end: number,
  ctx: BgpCodecContext,
  idPrefix: string,
): DecodedPathAttributes {
  const attributes: BgpPathAttribute[] = [];
  const nodes: DissectionNode[] = [];
  const notes: string[] = [];

  let cursor = start;
  let index = 0;

  while (cursor < end) {
    const attrStart = cursor;
    if (cursor + 3 > end) {
      notes.push(`Truncated path attribute header at byte ${cursor}.`);
      nodes.push({
        id: `${idPrefix}[${index}].truncated`,
        label: 'Truncated Path Attribute',
        value: `0x${toHexString(bytes.slice(cursor, end))}`,
        explanation: 'Fewer than 3 bytes remain in the Path Attributes section for Flags, Type Code, and Length.',
        reference: 'RFC 4271 §4.3',
        byteRange: { start: cursor, end },
      });
      break;
    }

    const flagsByte = bytes[cursor];
    const typeCode = bytes[cursor + 1];
    const extendedLength = (flagsByte & 0x10) !== 0;
    const lengthFieldWidth = extendedLength ? 2 : 1;

    if (cursor + 2 + lengthFieldWidth > end) {
      notes.push(`Truncated Extended Length field for attribute type ${typeCode} at byte ${cursor}.`);
      nodes.push({
        id: `${idPrefix}[${index}].truncated`,
        label: `Truncated Attribute (${typeCode})`,
        value: `0x${toHexString(bytes.slice(cursor, end))}`,
        explanation: 'Extended Length flag is set, requiring 2 length bytes, but fewer bytes remain.',
        reference: 'RFC 4271 §4.3',
        byteRange: { start: cursor, end },
      });
      break;
    }

    const attrLen = extendedLength
      ? readUint16BE(bytes, cursor + 2)
      : bytes[cursor + 2];
    const valueStart = cursor + 2 + lengthFieldWidth;
    const valueEnd = valueStart + attrLen;

    if (valueEnd > end) {
      notes.push(
        `Attribute type ${typeCode} at byte ${attrStart} claims length ${attrLen}, but only ${end - valueStart} bytes remain.`,
      );
      const partialVal = bytes.slice(valueStart, end);
      const flagsOverride = buildDecodedFlagsOverride(typeCode, partialVal.length, flagsByte);
      attributes.push({
        kind: 'raw',
        typeCode,
        ...(flagsOverride ? { flags: flagsOverride } : {}),
        lengthOverride: attrLen,
        dataHex: toHexString(partialVal),
      });
      const spec = getAttrSpec(typeCode);
      nodes.push({
        id: `${idPrefix}[${index}]`,
        label: `Truncated Attribute: ${spec.name} (${typeCode})`,
        value: `Declared ${attrLen} B, available ${partialVal.length} B`,
        explanation: 'Attribute length extends past Total Path Attribute Length.',
        reference: 'RFC 4271 §6.3',
        byteRange: { start: attrStart, end },
        children: [
          {
            id: `${idPrefix}[${index}].flags`,
            label: 'Attribute Flags',
            value: `0x${flagsByte.toString(16).padStart(2, '0')}`,
            explanation: 'Path attribute flags byte.',
            reference: 'RFC 4271 §4.3',
            byteRange: { start: attrStart, end: attrStart + 1 },
          },
          {
            id: `${idPrefix}[${index}].typeCode`,
            label: 'Attribute Type Code',
            value: `${typeCode} (${spec.name})`,
            explanation: `1-byte attribute type code (${spec.name}).`,
            reference: spec.reference,
            byteRange: { start: attrStart + 1, end: attrStart + 2 },
          },
          {
            id: `${idPrefix}[${index}].length`,
            label: 'Attribute Length',
            value: `${attrLen} bytes (truncated)`,
            explanation: 'Declared attribute length exceeds remaining path attribute bytes.',
            reference: 'RFC 4271 §6.3',
            byteRange: { start: attrStart + 2, end: valueStart },
          },
          ...(partialVal.length > 0
            ? [
                {
                  id: `${idPrefix}[${index}].data`,
                  label: 'Partial Attribute Value',
                  value: `0x${toHexString(partialVal)}`,
                  explanation: 'Partial attribute value bytes available before truncation.',
                  reference: 'RFC 4271 §4.3',
                  byteRange: { start: valueStart, end },
                },
              ]
            : []),
        ],
      });
      break;
    }

    const valueSlice = bytes.slice(valueStart, valueEnd);
    const flagsOverride = buildDecodedFlagsOverride(typeCode, valueSlice.length, flagsByte);
    const baseFlags = flagsOverride ? { flags: flagsOverride } : {};
    let decodedAttr: BgpPathAttribute | null = null;

    switch (typeCode) {
      case BGP_ATTR_TYPE.ORIGIN:
        if (valueSlice.length === 1 && valueSlice[0] <= 2) {
          decodedAttr = {
            kind: 'origin',
            ...baseFlags,
            origin: valueSlice[0] as 0 | 1 | 2,
          };
        } else {
          notes.push(`ORIGIN attribute at byte ${attrStart} has invalid value/length; kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.AS_PATH: {
        const asWidth: 2 | 4 = ctx.fourOctetAs ? 4 : 2;
        const segments = decodeAsPathSegments(valueSlice, asWidth);
        if (segments !== null) {
          decodedAttr = { kind: 'asPath', ...baseFlags, segments };
        } else {
          notes.push(
            `AS_PATH attribute at byte ${attrStart} failed ${asWidth}-byte AS decoding; kept as Raw.`,
          );
        }
        break;
      }

      case BGP_ATTR_TYPE.NEXT_HOP:
        if (valueSlice.length === 4) {
          decodedAttr = { kind: 'nextHop', ...baseFlags, nextHop: formatIPv4(valueSlice) };
        } else {
          notes.push(`NEXT_HOP attribute at byte ${attrStart} has length ${valueSlice.length} (expected 4); kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.MULTI_EXIT_DISC:
        if (valueSlice.length === 4) {
          decodedAttr = { kind: 'med', ...baseFlags, med: readUint32BE(valueSlice, 0) };
        } else {
          notes.push(`MULTI_EXIT_DISC at byte ${attrStart} has length ${valueSlice.length} (expected 4); kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.LOCAL_PREF:
        if (valueSlice.length === 4) {
          decodedAttr = { kind: 'localPref', ...baseFlags, localPref: readUint32BE(valueSlice, 0) };
        } else {
          notes.push(`LOCAL_PREF at byte ${attrStart} has length ${valueSlice.length} (expected 4); kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.ATOMIC_AGGREGATE:
        if (valueSlice.length === 0) {
          decodedAttr = { kind: 'atomicAggregate', ...baseFlags };
        } else {
          notes.push(`ATOMIC_AGGREGATE at byte ${attrStart} has non-zero length ${valueSlice.length}; kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.AGGREGATOR: {
        const asWidth: 2 | 4 = ctx.fourOctetAs ? 4 : 2;
        if (valueSlice.length === asWidth + 4) {
          const asn = asWidth === 4 ? readUint32BE(valueSlice, 0) : readUint16BE(valueSlice, 0);
          decodedAttr = {
            kind: 'aggregator',
            ...baseFlags,
            asn,
            ipAddress: formatIPv4(valueSlice.slice(asWidth, asWidth + 4)),
          };
        } else {
          notes.push(
            `AGGREGATOR at byte ${attrStart} has length ${valueSlice.length} (expected ${asWidth + 4} for ${asWidth}-byte AS); kept as Raw.`,
          );
        }
        break;
      }

      case BGP_ATTR_TYPE.COMMUNITIES:
        if (valueSlice.length % 4 === 0) {
          const communities: number[] = [];
          for (let off = 0; off < valueSlice.length; off += 4) {
            communities.push(readUint32BE(valueSlice, off));
          }
          decodedAttr = { kind: 'communities', ...baseFlags, communities };
        } else {
          notes.push(`COMMUNITIES at byte ${attrStart} length ${valueSlice.length} is not a multiple of 4; kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.MP_REACH_NLRI:
        if (valueSlice.length >= 5) {
          const afi = readUint16BE(valueSlice, 0);
          const safi = valueSlice[2];
          const nhLen = valueSlice[3];
          if (4 + nhLen + 1 <= valueSlice.length) {
            const nhSlice = valueSlice.slice(4, 4 + nhLen);
            const reserved = valueSlice[4 + nhLen];
            const nlriStart = valueStart + 4 + nhLen + 1;
            const addPath = hasAddPathForAfiSafi(ctx, afi, safi);

            let nextHops: string[] = [];
            let nextHopRawHex: string | undefined;
            if (afi === BGP_AFI.IPV6 && nhLen > 0 && nhLen % 16 === 0) {
              for (let off = 0; off < nhLen; off += 16) {
                nextHops.push(formatIPv6(nhSlice.slice(off, off + 16)));
              }
            } else if (afi === BGP_AFI.IPV4 && nhLen > 0 && nhLen % 4 === 0) {
              for (let off = 0; off < nhLen; off += 4) {
                nextHops.push(formatIPv4(nhSlice.slice(off, off + 4)));
              }
            } else if (nhLen > 0) {
              nextHopRawHex = toHexString(nhSlice);
            }

            if (afi === BGP_AFI.IPV4 || afi === BGP_AFI.IPV6) {
              const decodedNlri = decodePrefixList(
                bytes,
                nlriStart,
                valueEnd,
                afi,
                addPath,
                `${idPrefix}[${index}].nlri`,
                'Reachable MP-BGP route prefix',
              );
              if (decodedNlri.notes.length === 0) {
                decodedAttr = {
                  kind: 'mpReachNlri',
                  ...baseFlags,
                  afi,
                  safi,
                  nextHops,
                  ...(nextHopRawHex !== undefined ? { nextHopRawHex } : {}),
                  ...(reserved !== 0 ? { reserved } : {}),
                  nlri: decodedNlri.prefixes,
                };
              } else {
                notes.push(...decodedNlri.notes);
              }
            } else {
              notes.push(`MP_REACH_NLRI at byte ${attrStart} uses non-IPv4/IPv6 AFI ${afi}; kept as Raw.`);
            }
          } else {
            notes.push(`MP_REACH_NLRI at byte ${attrStart} has truncated next-hop field; kept as Raw.`);
          }
        } else {
          notes.push(`MP_REACH_NLRI at byte ${attrStart} is shorter than 5 bytes; kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.MP_UNREACH_NLRI:
        if (valueSlice.length >= 3) {
          const afi = readUint16BE(valueSlice, 0);
          const safi = valueSlice[2];
          const withdrawnStart = valueStart + 3;
          const addPath = hasAddPathForAfiSafi(ctx, afi, safi);
          if (afi === BGP_AFI.IPV4 || afi === BGP_AFI.IPV6) {
            const decodedWithdrawn = decodePrefixList(
              bytes,
              withdrawnStart,
              valueEnd,
              afi,
              addPath,
              `${idPrefix}[${index}].withdrawn`,
              'Withdrawn MP-BGP route prefix',
            );
            if (decodedWithdrawn.notes.length === 0) {
              decodedAttr = {
                kind: 'mpUnreachNlri',
                ...baseFlags,
                afi,
                safi,
                withdrawnRoutes: decodedWithdrawn.prefixes,
              };
            } else {
              notes.push(...decodedWithdrawn.notes);
            }
          } else {
            notes.push(`MP_UNREACH_NLRI at byte ${attrStart} uses non-IPv4/IPv6 AFI ${afi}; kept as Raw.`);
          }
        } else {
          notes.push(`MP_UNREACH_NLRI at byte ${attrStart} is shorter than 3 bytes; kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.AS4_PATH: {
        const segments = decodeAsPathSegments(valueSlice, 4);
        if (segments !== null) {
          decodedAttr = { kind: 'as4Path', ...baseFlags, segments };
        } else {
          notes.push(`AS4_PATH at byte ${attrStart} is malformed; kept as Raw.`);
        }
        break;
      }

      case BGP_ATTR_TYPE.AS4_AGGREGATOR:
        if (valueSlice.length === 8) {
          decodedAttr = {
            kind: 'as4Aggregator',
            ...baseFlags,
            asn: readUint32BE(valueSlice, 0),
            ipAddress: formatIPv4(valueSlice.slice(4, 8)),
          };
        } else {
          notes.push(`AS4_AGGREGATOR at byte ${attrStart} has length ${valueSlice.length} (expected 8); kept as Raw.`);
        }
        break;

      case BGP_ATTR_TYPE.LARGE_COMMUNITY:
        if (valueSlice.length % 12 === 0) {
          const communities: BgpLargeCommunity[] = [];
          for (let off = 0; off < valueSlice.length; off += 12) {
            communities.push({
              globalAdmin: readUint32BE(valueSlice, off),
              localData1: readUint32BE(valueSlice, off + 4),
              localData2: readUint32BE(valueSlice, off + 8),
            });
          }
          decodedAttr = { kind: 'largeCommunities', ...baseFlags, communities };
        } else {
          notes.push(`LARGE_COMMUNITY at byte ${attrStart} length ${valueSlice.length} is not a multiple of 12; kept as Raw.`);
        }
        break;

      default:
        break;
    }

    if (decodedAttr === null) {
      decodedAttr = {
        kind: 'raw',
        typeCode,
        ...baseFlags,
        dataHex: toHexString(valueSlice),
      };
    }

    const encodedForTree = encodePathAttribute(decodedAttr, ctx, attrStart, `${idPrefix}[${index}]`);
    if (encodedForTree.ok) {
      nodes.push(encodedForTree.value.node);
    }

    attributes.push(decodedAttr);
    cursor = valueEnd;
    index += 1;
  }

  return { attributes, nodes, notes };
}
