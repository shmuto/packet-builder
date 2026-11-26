import {
  parseHexBytes,
  readUint16BE,
  readUint32BE,
  toHexString,
  writeUint16BE,
  writeUint32BE,
} from '../bytes';
import { err, ok, type Result } from '../result';
import { isUint16, isUint32, isUint8 } from './common';
import {
  formatAfiSafi,
  getAddPathModeName,
  getCapabilityInfo,
} from './tables';
import {
  BGP_CAPABILITY_CODE,
  type BgpAddPathEntry,
  type BgpAddPathMode,
  type BgpCapability,
  type BgpGracefulRestartTuple,
  type DissectionNode,
} from './types';

export interface EncodedCapability {
  readonly bytes: Uint8Array;
  readonly node: DissectionNode;
}

export function encodeCapability(
  cap: BgpCapability,
  baseOffset: number,
  idPrefix: string,
): Result<EncodedCapability> {
  let code: number;
  let valueBytes: Uint8Array;
  const valueStart = baseOffset + 2;
  const valueChildren: DissectionNode[] = [];
  let summaryValue: string;

  switch (cap.kind) {
    case 'mp': {
      if (!isUint16(cap.afi) || !isUint8(cap.safi)) {
        return err(`Multiprotocol capability has invalid AFI/SAFI (${cap.afi}/${cap.safi}).`);
      }
      const reserved = cap.reserved ?? 0;
      if (!isUint8(reserved)) {
        return err(`Multiprotocol capability reserved byte must be 0-255 (got ${reserved}).`);
      }
      code = BGP_CAPABILITY_CODE.MULTIPROTOCOL;
      valueBytes = new Uint8Array(4);
      writeUint16BE(valueBytes, 0, cap.afi);
      valueBytes[2] = reserved;
      valueBytes[3] = cap.safi;
      summaryValue = formatAfiSafi(cap.afi, cap.safi);
      valueChildren.push(
        {
          id: `${idPrefix}.afi`,
          label: 'AFI',
          value: `${cap.afi} (${formatAfiSafi(cap.afi, cap.safi).split(' ')[0]})`,
          explanation: 'Address Family Identifier indicating the network-layer protocol (1 = IPv4, 2 = IPv6).',
          reference: 'RFC 4760 §8',
          byteRange: { start: valueStart, end: valueStart + 2 },
        },
        {
          id: `${idPrefix}.reserved`,
          label: 'Reserved',
          value: `0x${reserved.toString(16).padStart(2, '0')}`,
          explanation: 'Reserved octet set to 0 by the sender and ignored by the receiver.',
          reference: 'RFC 4760 §8',
          byteRange: { start: valueStart + 2, end: valueStart + 3 },
        },
        {
          id: `${idPrefix}.safi`,
          label: 'SAFI',
          value: String(cap.safi),
          explanation: 'Subsequent Address Family Identifier narrowing the routing table (1 = Unicast, 2 = Multicast).',
          reference: 'RFC 4760 §8',
          byteRange: { start: valueStart + 3, end: valueStart + 4 },
        },
      );
      break;
    }

    case 'routeRefresh': {
      code = BGP_CAPABILITY_CODE.ROUTE_REFRESH;
      valueBytes = new Uint8Array(0);
      summaryValue = 'Enabled (length 0)';
      break;
    }

    case 'gracefulRestart': {
      if (!Number.isInteger(cap.restartFlags) || cap.restartFlags < 0 || cap.restartFlags > 0x0f) {
        return err(`Graceful Restart flags must be 0-15 (got ${cap.restartFlags}).`);
      }
      if (!Number.isInteger(cap.restartTime) || cap.restartTime < 0 || cap.restartTime > 0x0fff) {
        return err(`Graceful Restart time must be 0-4095 seconds (got ${cap.restartTime}).`);
      }
      code = BGP_CAPABILITY_CODE.GRACEFUL_RESTART;
      const totalValueLen = 2 + cap.tuples.length * 4;
      if (totalValueLen > 255) {
        return err(`Graceful Restart capability value exceeds 255 bytes (${totalValueLen} bytes).`);
      }
      valueBytes = new Uint8Array(totalValueLen);
      const flagsAndTime = ((cap.restartFlags & 0x0f) << 12) | (cap.restartTime & 0x0fff);
      writeUint16BE(valueBytes, 0, flagsAndTime);
      const rFlag = (cap.restartFlags & 0x08) !== 0;
      const nFlag = (cap.restartFlags & 0x04) !== 0;
      valueChildren.push({
        id: `${idPrefix}.flagsAndTime`,
        label: 'Restart Flags & Time',
        value: `Flags 0x${cap.restartFlags.toString(16)} (R=${rFlag ? 1 : 0}, N=${nFlag ? 1 : 0}), Restart Time ${cap.restartTime}s`,
        explanation:
          'Top 4 bits carry Restart Flags (R=1 means this router just restarted; N=1 enables graceful notification); low 12 bits specify max seconds to retain stale routes.',
        reference: 'RFC 4724 §3',
        byteRange: { start: valueStart, end: valueStart + 2 },
      });

      for (let i = 0; i < cap.tuples.length; i++) {
        const tuple = cap.tuples[i];
        if (!isUint16(tuple.afi) || !isUint8(tuple.safi)) {
          return err(`Graceful Restart tuple #${i + 1} has invalid AFI/SAFI.`);
        }
        const extraFlags = tuple.reservedFlags ?? 0;
        if (!Number.isInteger(extraFlags) || extraFlags < 0 || extraFlags > 0x7f) {
          return err(`Graceful Restart tuple #${i + 1} reserved flags must be 0-127.`);
        }
        const tupleOffset = 2 + i * 4;
        const absOffset = valueStart + tupleOffset;
        const afFlags = (tuple.forwardingState ? 0x80 : 0) | (extraFlags & 0x7f);
        writeUint16BE(valueBytes, tupleOffset, tuple.afi);
        valueBytes[tupleOffset + 2] = tuple.safi;
        valueBytes[tupleOffset + 3] = afFlags;

        valueChildren.push({
          id: `${idPrefix}.tuples[${i}]`,
          label: `GR Entry #${i + 1}`,
          value: `${formatAfiSafi(tuple.afi, tuple.safi)}, Forwarding State=${tuple.forwardingState ? 'Preserved (F=1)' : 'Not preserved (F=0)'}`,
          explanation:
            'Per-address-family Graceful Restart entry. The F-bit tells the peer whether forwarding state for this family survived the restart.',
          reference: 'RFC 4724 §3',
          byteRange: { start: absOffset, end: absOffset + 4 },
          children: [
            {
              id: `${idPrefix}.tuples[${i}].afi`,
              label: 'AFI',
              value: String(tuple.afi),
              explanation: 'Address Family Identifier protected by Graceful Restart.',
              reference: 'RFC 4724 §3',
              byteRange: { start: absOffset, end: absOffset + 2 },
            },
            {
              id: `${idPrefix}.tuples[${i}].safi`,
              label: 'SAFI',
              value: String(tuple.safi),
              explanation: 'Subsequent Address Family Identifier protected by Graceful Restart.',
              reference: 'RFC 4724 §3',
              byteRange: { start: absOffset + 2, end: absOffset + 3 },
            },
            {
              id: `${idPrefix}.tuples[${i}].flags`,
              label: 'Flags for Address Family',
              value: `0x${afFlags.toString(16).padStart(2, '0')} (F=${tuple.forwardingState ? 1 : 0})`,
              explanation: 'Most significant bit (0x80) is the Forwarding State (F) bit; remaining 7 bits are reserved.',
              reference: 'RFC 4724 §3',
              byteRange: { start: absOffset + 3, end: absOffset + 4 },
            },
          ],
        });
      }

      summaryValue = `Restart Time ${cap.restartTime}s, ${cap.tuples.length} ${cap.tuples.length === 1 ? 'family' : 'families'}`;
      break;
    }

    case 'fourOctetAs': {
      if (!isUint32(cap.asn)) {
        return err(`4-octet AS capability ASN must be a 32-bit unsigned integer (got ${cap.asn}).`);
      }
      code = BGP_CAPABILITY_CODE.FOUR_OCTET_AS;
      valueBytes = new Uint8Array(4);
      writeUint32BE(valueBytes, 0, cap.asn);
      summaryValue = `AS ${cap.asn}`;
      valueChildren.push({
        id: `${idPrefix}.asn`,
        label: '4-octet AS Number',
        value: String(cap.asn),
        explanation:
          'The speaker’s full 32-bit Autonomous System Number; used because the fixed OPEN My AS field is only 16 bits wide.',
        reference: 'RFC 6793 §3',
        byteRange: { start: valueStart, end: valueStart + 4 },
      });
      break;
    }

    case 'addPath': {
      code = BGP_CAPABILITY_CODE.ADD_PATH;
      const totalValueLen = cap.entries.length * 4;
      if (totalValueLen > 255) {
        return err(`ADD-PATH capability value exceeds 255 bytes (${totalValueLen} bytes).`);
      }
      valueBytes = new Uint8Array(totalValueLen);
      for (let i = 0; i < cap.entries.length; i++) {
        const entry = cap.entries[i];
        if (!isUint16(entry.afi) || !isUint8(entry.safi)) {
          return err(`ADD-PATH entry #${i + 1} has invalid AFI/SAFI.`);
        }
        if (entry.sendReceive !== 1 && entry.sendReceive !== 2 && entry.sendReceive !== 3) {
          return err(`ADD-PATH Send/Receive value must be 1, 2, or 3 (got ${entry.sendReceive}).`);
        }
        const entryOffset = i * 4;
        const absOffset = valueStart + entryOffset;
        writeUint16BE(valueBytes, entryOffset, entry.afi);
        valueBytes[entryOffset + 2] = entry.safi;
        valueBytes[entryOffset + 3] = entry.sendReceive;
        valueChildren.push({
          id: `${idPrefix}.entries[${i}]`,
          label: `ADD-PATH Entry #${i + 1}`,
          value: `${formatAfiSafi(entry.afi, entry.safi)} — ${getAddPathModeName(entry.sendReceive)}`,
          explanation:
            'Negotiates whether this router can receive (1), send (2), or both send and receive (3) multiple paths per prefix for this family.',
          reference: 'RFC 7911 §4',
          byteRange: { start: absOffset, end: absOffset + 4 },
          children: [
            {
              id: `${idPrefix}.entries[${i}].afi`,
              label: 'AFI',
              value: String(entry.afi),
              explanation: 'Address Family Identifier for ADD-PATH.',
              reference: 'RFC 7911 §4',
              byteRange: { start: absOffset, end: absOffset + 2 },
            },
            {
              id: `${idPrefix}.entries[${i}].safi`,
              label: 'SAFI',
              value: String(entry.safi),
              explanation: 'Subsequent Address Family Identifier for ADD-PATH.',
              reference: 'RFC 7911 §4',
              byteRange: { start: absOffset + 2, end: absOffset + 3 },
            },
            {
              id: `${idPrefix}.entries[${i}].sendReceive`,
              label: 'Send/Receive',
              value: `${entry.sendReceive} (${getAddPathModeName(entry.sendReceive)})`,
              explanation: '1 = Receive multiple paths, 2 = Send multiple paths, 3 = Send and Receive.',
              reference: 'RFC 7911 §4',
              byteRange: { start: absOffset + 3, end: absOffset + 4 },
            },
          ],
        });
      }
      summaryValue =
        cap.entries.length === 0
          ? 'No entries'
          : cap.entries
              .map((e) => `${formatAfiSafi(e.afi, e.safi)} (${getAddPathModeName(e.sendReceive)})`)
              .join(', ');
      break;
    }

    case 'enhancedRouteRefresh': {
      code = BGP_CAPABILITY_CODE.ENHANCED_ROUTE_REFRESH;
      valueBytes = new Uint8Array(0);
      summaryValue = 'Enabled (length 0)';
      break;
    }

    case 'raw': {
      if (!isUint8(cap.code)) {
        return err(`Raw capability code must be 0-255 (got ${cap.code}).`);
      }
      const parsed = parseHexBytes(cap.dataHex);
      if (!parsed.ok) {
        return err(`Raw capability (code ${cap.code}) dataHex error: ${parsed.error}`);
      }
      if (parsed.value.length > 255) {
        return err(`Raw capability (code ${cap.code}) data exceeds 255 bytes (${parsed.value.length}).`);
      }
      code = cap.code;
      valueBytes = parsed.value;
      summaryValue = valueBytes.length === 0 ? '(empty)' : `0x${toHexString(valueBytes)}`;
      if (valueBytes.length > 0) {
        valueChildren.push({
          id: `${idPrefix}.data`,
          label: 'Capability Value',
          value: `0x${toHexString(valueBytes)} (${valueBytes.length} ${valueBytes.length === 1 ? 'byte' : 'bytes'})`,
          explanation: 'Opaque capability-specific data carried inside Optional Parameter Type 2.',
          reference: 'RFC 5492 §4',
          byteRange: { start: valueStart, end: valueStart + valueBytes.length },
        });
      }
      break;
    }
  }

  const info = getCapabilityInfo(code);
  const bytes = new Uint8Array(2 + valueBytes.length);
  bytes[0] = code;
  bytes[1] = valueBytes.length;
  bytes.set(valueBytes, 2);

  const children: DissectionNode[] = [
    {
      id: `${idPrefix}.code`,
      label: 'Capability Code',
      value: `${code} (${info.name})`,
      explanation: `1-byte IANA-assigned capability code identifying "${info.name}".`,
      reference: info.reference,
      byteRange: { start: baseOffset, end: baseOffset + 1 },
    },
    {
      id: `${idPrefix}.length`,
      label: 'Capability Length',
      value: `${valueBytes.length} ${valueBytes.length === 1 ? 'byte' : 'bytes'}`,
      explanation: 'Length in octets of the Capability Value field that immediately follows.',
      reference: 'RFC 5492 §4',
      byteRange: { start: baseOffset + 1, end: baseOffset + 2 },
    },
    ...valueChildren,
  ];

  const node: DissectionNode = {
    id: idPrefix,
    label: `Capability: ${info.name} (${code})`,
    value: summaryValue,
    explanation: info.explanation,
    reference: info.reference,
    byteRange: { start: baseOffset, end: baseOffset + bytes.length },
    children,
  };

  return ok({ bytes, node });
}

export interface DecodedCapabilities {
  readonly capabilities: readonly BgpCapability[];
  readonly nodes: readonly DissectionNode[];
  readonly notes: readonly string[];
}

export function decodeCapabilitiesSlice(
  bytes: Uint8Array,
  start: number,
  end: number,
  idPrefix: string,
): DecodedCapabilities {
  const capabilities: BgpCapability[] = [];
  const nodes: DissectionNode[] = [];
  const notes: string[] = [];

  let cursor = start;
  let index = 0;

  while (cursor < end) {
    const capStart = cursor;
    if (cursor + 2 > end) {
      notes.push(`Truncated capability header at byte ${cursor}.`);
      nodes.push({
        id: `${idPrefix}[${index}].truncated`,
        label: 'Truncated Capability Header',
        value: `0x${toHexString(bytes.slice(cursor, end))}`,
        explanation: 'Fewer than 2 bytes remain in Optional Parameter Type 2 for a capability Code and Length.',
        reference: 'RFC 5492 §4',
        byteRange: { start: cursor, end },
      });
      break;
    }

    const code = bytes[cursor];
    const len = bytes[cursor + 1];
    const valueStart = cursor + 2;
    const valueEnd = valueStart + len;

    if (valueEnd > end) {
      notes.push(
        `Capability code ${code} at byte ${capStart} claims length ${len}, but only ${end - valueStart} bytes remain.`,
      );
      const rawData = bytes.slice(valueStart, end);
      capabilities.push({ kind: 'raw', code, dataHex: toHexString(rawData) });
      nodes.push({
        id: `${idPrefix}[${index}]`,
        label: `Truncated Capability (${code})`,
        value: `Declared ${len} B, available ${rawData.length} B`,
        explanation: 'Capability length extends past the end of the Optional Parameter.',
        reference: 'RFC 5492 §4',
        byteRange: { start: capStart, end },
        children: [
          {
            id: `${idPrefix}[${index}].code`,
            label: 'Capability Code',
            value: `${code} (${getCapabilityInfo(code).name})`,
            explanation: '1-byte BGP capability code.',
            reference: 'RFC 5492 §4',
            byteRange: { start: capStart, end: capStart + 1 },
          },
          {
            id: `${idPrefix}[${index}].length`,
            label: 'Capability Length',
            value: `${len} bytes (truncated)`,
            explanation: 'Declared capability length exceeds remaining Optional Parameter bytes.',
            reference: 'RFC 5492 §4',
            byteRange: { start: capStart + 1, end: capStart + 2 },
          },
          ...(rawData.length > 0
            ? [
                {
                  id: `${idPrefix}[${index}].data`,
                  label: 'Partial Capability Value',
                  value: `0x${toHexString(rawData)}`,
                  explanation: 'Partial bytes available before the Optional Parameter ended.',
                  reference: 'RFC 5492 §4',
                  byteRange: { start: valueStart, end },
                },
              ]
            : []),
        ],
      });
      break;
    }

    const valueSlice = bytes.slice(valueStart, valueEnd);
    let decodedCap: BgpCapability | null = null;

    if (code === BGP_CAPABILITY_CODE.MULTIPROTOCOL && len === 4) {
      decodedCap = {
        kind: 'mp',
        afi: readUint16BE(valueSlice, 0),
        reserved: valueSlice[2],
        safi: valueSlice[3],
      };
    } else if (code === BGP_CAPABILITY_CODE.ROUTE_REFRESH && len === 0) {
      decodedCap = { kind: 'routeRefresh' };
    } else if (code === BGP_CAPABILITY_CODE.GRACEFUL_RESTART && len >= 2 && (len - 2) % 4 === 0) {
      const firstTwo = readUint16BE(valueSlice, 0);
      const restartFlags = (firstTwo >>> 12) & 0x0f;
      const restartTime = firstTwo & 0x0fff;
      const tuples: BgpGracefulRestartTuple[] = [];
      for (let off = 2; off < len; off += 4) {
        const afFlags = valueSlice[off + 3];
        tuples.push({
          afi: readUint16BE(valueSlice, off),
          safi: valueSlice[off + 2],
          forwardingState: (afFlags & 0x80) !== 0,
          ...(afFlags & 0x7f ? { reservedFlags: afFlags & 0x7f } : {}),
        });
      }
      decodedCap = { kind: 'gracefulRestart', restartFlags, restartTime, tuples };
    } else if (code === BGP_CAPABILITY_CODE.FOUR_OCTET_AS && len === 4) {
      decodedCap = { kind: 'fourOctetAs', asn: readUint32BE(valueSlice, 0) };
    } else if (code === BGP_CAPABILITY_CODE.ADD_PATH && len % 4 === 0) {
      const entries: BgpAddPathEntry[] = [];
      let allModesValid = true;
      for (let off = 0; off < len; off += 4) {
        const mode = valueSlice[off + 3];
        if (mode !== 1 && mode !== 2 && mode !== 3) {
          allModesValid = false;
          break;
        }
        entries.push({
          afi: readUint16BE(valueSlice, off),
          safi: valueSlice[off + 2],
          sendReceive: mode as BgpAddPathMode,
        });
      }
      if (allModesValid) {
        decodedCap = { kind: 'addPath', entries };
      } else {
        notes.push(`ADD-PATH capability at byte ${capStart} has invalid Send/Receive value; kept as Raw.`);
      }
    } else if (code === BGP_CAPABILITY_CODE.ENHANCED_ROUTE_REFRESH && len === 0) {
      decodedCap = { kind: 'enhancedRouteRefresh' };
    } else {
      if (
        code === BGP_CAPABILITY_CODE.MULTIPROTOCOL ||
        code === BGP_CAPABILITY_CODE.ROUTE_REFRESH ||
        code === BGP_CAPABILITY_CODE.GRACEFUL_RESTART ||
        code === BGP_CAPABILITY_CODE.FOUR_OCTET_AS ||
        code === BGP_CAPABILITY_CODE.ADD_PATH ||
        code === BGP_CAPABILITY_CODE.ENHANCED_ROUTE_REFRESH
      ) {
        notes.push(
          `Known capability code ${code} at byte ${capStart} has unexpected length ${len}; kept as Raw.`,
        );
      }
      decodedCap = { kind: 'raw', code, dataHex: toHexString(valueSlice) };
    }

    if (decodedCap === null) {
      decodedCap = { kind: 'raw', code, dataHex: toHexString(valueSlice) };
    }

    const encodedForTree = encodeCapability(decodedCap, capStart, `${idPrefix}[${index}]`);
    if (encodedForTree.ok) {
      nodes.push(encodedForTree.value.node);
    }
    capabilities.push(decodedCap);
    cursor = valueEnd;
    index += 1;
  }

  return { capabilities, nodes, notes };
}
