import {
  formatIPv4,
  parseHexOrDump,
  readUint16BE,
  toHexString,
} from '../bytes';
import { decodePathAttributesSlice } from './attributes';
import { decodeCapabilitiesSlice } from './capabilities';
import { buildCommonHeaderNode } from './common';
import { encodeBgpMessage } from './encode';
import { decodePrefixList } from './prefix';
import {
  formatAfiSafi,
  getAfiName,
  getNotificationErrorInfo,
  getNotificationSubcodeInfo,
  getRouteRefreshSubtypeInfo,
  getSafiName,
} from './tables';
import {
  BGP_AFI,
  BGP_AS_TRANS,
  BGP_HEADER_LENGTH,
  BGP_MARKER_LENGTH,
  BGP_MAX_MESSAGE_LENGTH,
  BGP_MESSAGE_TYPE,
  BGP_SAFI,
  DEFAULT_BGP_CODEC_CONTEXT,
  hasAddPathForAfiSafi,
  type BgpCapability,
  type BgpCodecContext,
  type BgpDecodeResult,
  type BgpMessage,
  type BgpNotificationMessage,
  type BgpOpenMessage,
  type BgpOptionalParameter,
  type BgpRawOptionalParameter,
  type BgpRouteRefreshMessage,
  type BgpUpdateMessage,
  type DecodedBgpMessage,
  type DissectionNode,
} from './types';

function decodeSingleMessage(
  msgBytes: Uint8Array,
  streamOffset: number,
  ctx: BgpCodecContext,
): DecodedBgpMessage {
  const notes: string[] = [];
  const markerBytes = msgBytes.slice(0, BGP_MARKER_LENGTH);
  const markerAllOnes = markerBytes.every((b) => b === 0xff);
  const markerOverride = markerAllOnes ? undefined : toHexString(markerBytes);
  if (!markerAllOnes) {
    notes.push(
      `Message at byte ${streamOffset} has a non-standard Marker (expected 16 bytes of 0xff).`,
    );
  }

  const declaredLength = readUint16BE(msgBytes, 16);
  const typeCode = msgBytes[18];
  if (declaredLength > BGP_MAX_MESSAGE_LENGTH) {
    notes.push(
      `Message at byte ${streamOffset} has length ${declaredLength}, exceeding the classic 4096-byte RFC 4271 limit.`,
    );
  }

  const headerNode = buildCommonHeaderNode(
    markerBytes,
    declaredLength,
    msgBytes.length,
    typeCode,
    declaredLength !== msgBytes.length,
  );

  const tryEncodeTree = (message: BgpMessage, fallbackTree: DissectionNode): DissectionNode => {
    const encoded = encodeBgpMessage(message, ctx);
    if (encoded.ok && encoded.value.bytes.length === msgBytes.length) {
      let identical = true;
      for (let i = 0; i < msgBytes.length; i++) {
        if (encoded.value.bytes[i] !== msgBytes[i]) {
          identical = false;
          break;
        }
      }
      if (identical) {
        return encoded.value.tree;
      }
    }
    return fallbackTree;
  };

  switch (typeCode) {
    case BGP_MESSAGE_TYPE.OPEN: {
      if (msgBytes.length < 29) {
        notes.push(
          `OPEN message at byte ${streamOffset} is too short (${msgBytes.length} bytes; minimum is 29).`,
        );
        const rawBody = msgBytes.slice(19);
        const fallbackMsg: BgpMessage = {
          type: 'unknown',
          ...(markerOverride ? { markerHex: markerOverride } : {}),
          typeCode,
          bodyHex: toHexString(rawBody),
        };
        const tree: DissectionNode = {
          id: 'bgp',
          label: 'BGP OPEN Message (Malformed)',
          value: `Truncated (${msgBytes.length} bytes)`,
          explanation: 'OPEN message is shorter than the 29-byte minimum required by RFC 4271 §4.2.',
          reference: 'RFC 4271 §4.2 / §6.1',
          byteRange: { start: 0, end: msgBytes.length },
          children: [
            headerNode,
            ...(rawBody.length > 0
              ? [
                  {
                    id: 'open.truncated',
                    label: 'Truncated OPEN Body',
                    value: `0x${toHexString(rawBody)}`,
                    explanation: 'Partial OPEN body bytes before the message ended.',
                    reference: 'RFC 4271 §4.2',
                    byteRange: { start: 19, end: msgBytes.length },
                  },
                ]
              : []),
          ],
        };
        return { message: fallbackMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
      }

      const version = msgBytes[19];
      const myAs = readUint16BE(msgBytes, 20);
      const holdTime = readUint16BE(msgBytes, 22);
      const bgpIdentifier = formatIPv4(msgBytes.slice(24, 28));
      const optParamLen = msgBytes[28];
      const availableOptLen = msgBytes.length - 29;
      const optEnd = Math.min(29 + optParamLen, msgBytes.length);

      if (optParamLen > availableOptLen) {
        notes.push(
          `OPEN Optional Parameters Length (${optParamLen}) exceeds available body bytes (${availableOptLen}).`,
        );
      } else if (optParamLen < availableOptLen) {
        notes.push(
          `OPEN has ${availableOptLen - optParamLen} trailing byte(s) after Optional Parameters.`,
        );
      }

      const capabilities: BgpCapability[] = [];
      const extraOptionalParameters: BgpRawOptionalParameter[] = [];
      const decodedOptParams: BgpOptionalParameter[] = [];
      const optParamNodes: DissectionNode[] = [];
      let cursor = 29;
      let pIdx = 0;

      while (cursor < optEnd) {
        const pStart = cursor;
        if (cursor + 2 > optEnd) {
          notes.push(`Truncated Optional Parameter header at byte ${cursor}.`);
          optParamNodes.push({
            id: `open.optParams[${pIdx}].truncated`,
            label: 'Truncated Optional Parameter',
            value: `0x${toHexString(msgBytes.slice(cursor, optEnd))}`,
            explanation: 'Fewer than 2 bytes remain for Optional Parameter Type and Length.',
            reference: 'RFC 4271 §4.2',
            byteRange: { start: cursor, end: optEnd },
          });
          cursor = optEnd;
          break;
        }
        const pType = msgBytes[cursor];
        const pLen = msgBytes[cursor + 1];
        const pValStart = cursor + 2;
        const pValEnd = Math.min(pValStart + pLen, optEnd);

        if (pValStart + pLen > optEnd) {
          notes.push(
            `Optional Parameter type ${pType} at byte ${pStart} declares length ${pLen}, but only ${optEnd - pValStart} bytes remain.`,
          );
        }

        if (pType === 2) {
          const decodedCaps = decodeCapabilitiesSlice(
            msgBytes,
            pValStart,
            pValEnd,
            `open.optParams[${pIdx}].cap`,
          );
          capabilities.push(...decodedCaps.capabilities);
          notes.push(...decodedCaps.notes);
          decodedOptParams.push({
            kind: 'capabilities',
            capabilities: decodedCaps.capabilities,
            ...(pLen !== pValEnd - pValStart ? { lengthOverride: pLen } : {}),
          });
          optParamNodes.push({
            id: `open.optParams[${pIdx}]`,
            label: 'Optional Parameter: Capabilities (Type 2)',
            value: `${decodedCaps.capabilities.length} ${decodedCaps.capabilities.length === 1 ? 'capability' : 'capabilities'} (${pValEnd - pValStart} bytes)`,
            explanation:
              'Optional Parameter Type 2 carries BGP capability TLVs so peers can negotiate features like MP-BGP, 4-octet AS, and Route Refresh.',
            reference: 'RFC 5492 §4',
            byteRange: { start: pStart, end: pValEnd },
            children: [
              {
                id: `open.optParams[${pIdx}].type`,
                label: 'Parameter Type',
                value: '2 (Capabilities)',
                explanation: 'Optional Parameter Type 2 identifies the Capabilities parameter.',
                reference: 'RFC 5492 §4',
                byteRange: { start: pStart, end: pStart + 1 },
              },
              {
                id: `open.optParams[${pIdx}].length`,
                label: 'Parameter Length',
                value: `${pLen} bytes`,
                explanation: 'Total length in octets of the capability TLVs inside this Optional Parameter.',
                reference: 'RFC 5492 §4',
                byteRange: { start: pStart + 1, end: pStart + 2 },
              },
              ...decodedCaps.nodes,
            ],
          });
        } else {
          const rawVal = msgBytes.slice(pValStart, pValEnd);
          const rawParam = {
            type: pType,
            dataHex: toHexString(rawVal),
            ...(pLen !== rawVal.length ? { lengthOverride: pLen } : {}),
          };
          extraOptionalParameters.push(rawParam);
          decodedOptParams.push({ kind: 'raw', ...rawParam });
          optParamNodes.push({
            id: `open.optParams[${pIdx}]`,
            label: `Optional Parameter (Type ${pType})`,
            value: rawVal.length === 0 ? '(empty)' : `0x${toHexString(rawVal)}`,
            explanation: 'Non-Capabilities Optional Parameter carried in the BGP OPEN message.',
            reference: 'RFC 4271 §4.2',
            byteRange: { start: pStart, end: pValEnd },
            children: [
              {
                id: `open.optParams[${pIdx}].type`,
                label: 'Parameter Type',
                value: String(pType),
                explanation: '1-byte Optional Parameter type code.',
                reference: 'RFC 4271 §4.2',
                byteRange: { start: pStart, end: pStart + 1 },
              },
              {
                id: `open.optParams[${pIdx}].length`,
                label: 'Parameter Length',
                value: `${pLen} bytes`,
                explanation: 'Length of this Optional Parameter value in octets.',
                reference: 'RFC 4271 §4.2',
                byteRange: { start: pStart + 1, end: pStart + 2 },
              },
              ...(rawVal.length > 0
                ? [
                    {
                      id: `open.optParams[${pIdx}].value`,
                      label: 'Parameter Value',
                      value: `0x${toHexString(rawVal)}`,
                      explanation: 'Opaque Optional Parameter value bytes.',
                      reference: 'RFC 4271 §4.2',
                      byteRange: { start: pValStart, end: pValEnd },
                    },
                  ]
                : []),
            ],
          });
        }

        cursor = pValEnd;
        pIdx += 1;
      }

      const as4Cap = capabilities.find(
        (c): c is Extract<BgpCapability, { kind: 'fourOctetAs' }> => c.kind === 'fourOctetAs',
      );
      const asn = as4Cap ? as4Cap.asn : myAs;
      const expectedAutoMyAs = asn <= 0xffff ? asn : BGP_AS_TRANS;
      const myAsOverride = myAs !== expectedAutoMyAs ? myAs : undefined;
      const needsExplicitOptParams =
        decodedOptParams.length > 1 ||
        decodedOptParams.some(
          (p) => p.kind === 'raw' || p.lengthOverride !== undefined,
        );

      const openMsg: BgpOpenMessage = {
        type: 'open',
        ...(markerOverride ? { markerHex: markerOverride } : {}),
        version,
        asn,
        ...(myAsOverride !== undefined ? { myAsOverride } : {}),
        holdTime,
        bgpIdentifier,
        capabilities,
        ...(needsExplicitOptParams ? { optionalParameters: decodedOptParams } : {}),
        ...(extraOptionalParameters.length > 0 ? { extraOptionalParameters } : {}),
        ...(optParamLen !== availableOptLen ? { optParamLengthOverride: optParamLen } : {}),
      };

      const bodyChildren: DissectionNode[] = [
        {
          id: 'open.version',
          label: 'Version',
          value: String(version),
          explanation: 'BGP protocol version number. Modern BGP always uses version 4.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 19, end: 20 },
        },
        {
          id: 'open.myAs',
          label: 'My Autonomous System',
          value: myAs === BGP_AS_TRANS ? `${myAs} (AS_TRANS)` : String(myAs),
          explanation:
            '16-bit Autonomous System Number of the sending BGP speaker (or AS_TRANS 23456 when the speaker has a 4-octet ASN > 65535).',
          reference: myAs === BGP_AS_TRANS ? 'RFC 4271 §4.2 / RFC 6793 §3' : 'RFC 4271 §4.2',
          byteRange: { start: 20, end: 22 },
        },
        {
          id: 'open.holdTime',
          label: 'Hold Time',
          value: holdTime === 0 ? '0 s (Hold Timer disabled)' : `${holdTime} s`,
          explanation: 'Proposed maximum seconds allowed between successive KEEPALIVE or UPDATE messages.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 22, end: 24 },
        },
        {
          id: 'open.bgpIdentifier',
          label: 'BGP Identifier',
          value: bgpIdentifier,
          explanation: '32-bit IPv4-formatted Router ID uniquely identifying this BGP speaker within its AS.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 24, end: 28 },
        },
        {
          id: 'open.optParamLength',
          label: 'Optional Parameters Length',
          value: `${optParamLen} bytes`,
          explanation: 'Total length in octets of the Optional Parameters field that follows.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 28, end: 29 },
        },
      ];
      if (optEnd > 29) {
        bodyChildren.push({
          id: 'open.optParams',
          label: 'Optional Parameters',
          value: `${optParamNodes.length} ${optParamNodes.length === 1 ? 'parameter' : 'parameters'} (${optEnd - 29} bytes)`,
          explanation: 'TLV-encoded Optional Parameters, primarily carrying BGP Capabilities (Type 2).',
          reference: 'RFC 4271 §4.2 / RFC 5492 §4',
          byteRange: { start: 29, end: optEnd },
          children: optParamNodes,
        });
      }
      if (optEnd < msgBytes.length) {
        bodyChildren.push({
          id: 'open.trailing',
          label: 'Trailing Bytes',
          value: `0x${toHexString(msgBytes.slice(optEnd))}`,
          explanation: 'Extra bytes present after Optional Parameters Length.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: optEnd, end: msgBytes.length },
        });
      }

      const fallbackTree: DissectionNode = {
        id: 'bgp',
        label: 'BGP OPEN Message',
        value: `AS ${asn}, Hold ${holdTime}s, Router ID ${bgpIdentifier}, ${capabilities.length} ${capabilities.length === 1 ? 'cap' : 'caps'}`,
        explanation:
          'First BGP message sent after TCP connects. Advertises the speaker’s ASN, Hold Time, Router ID, and supported capabilities.',
        reference: 'RFC 4271 §4.2',
        byteRange: { start: 0, end: msgBytes.length },
        children: [headerNode, ...bodyChildren],
      };

      const tree = tryEncodeTree(openMsg, fallbackTree);
      return { message: openMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
    }

    case BGP_MESSAGE_TYPE.UPDATE: {
      if (msgBytes.length < 23) {
        notes.push(
          `UPDATE message at byte ${streamOffset} is too short (${msgBytes.length} bytes; minimum is 23).`,
        );
        const rawBody = msgBytes.slice(19);
        const fallbackMsg: BgpMessage = {
          type: 'unknown',
          ...(markerOverride ? { markerHex: markerOverride } : {}),
          typeCode,
          bodyHex: toHexString(rawBody),
        };
        const tree: DissectionNode = {
          id: 'bgp',
          label: 'BGP UPDATE Message (Malformed)',
          value: `Truncated (${msgBytes.length} bytes)`,
          explanation: 'UPDATE message is shorter than the 23-byte minimum required by RFC 4271 §4.3.',
          reference: 'RFC 4271 §4.3 / §6.1',
          byteRange: { start: 0, end: msgBytes.length },
          children: [
            headerNode,
            ...(rawBody.length > 0
              ? [
                  {
                    id: 'update.truncated',
                    label: 'Truncated UPDATE Body',
                    value: `0x${toHexString(rawBody)}`,
                    explanation: 'Partial UPDATE body bytes before the message ended.',
                    reference: 'RFC 4271 §4.3',
                    byteRange: { start: 19, end: msgBytes.length },
                  },
                ]
              : []),
          ],
        };
        return { message: fallbackMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
      }

      const ipv4AddPath = hasAddPathForAfiSafi(ctx, BGP_AFI.IPV4, BGP_SAFI.UNICAST);
      const withdrawnLen = readUint16BE(msgBytes, 19);
      const withdrawnStart = 21;
      const withdrawnEnd = Math.min(withdrawnStart + withdrawnLen, msgBytes.length);

      const bodyChildren: DissectionNode[] = [
        {
          id: 'update.withdrawnLength',
          label: 'Withdrawn Routes Length',
          value: `${withdrawnLen} bytes`,
          explanation: 'Total length in octets of the IPv4 Withdrawn Routes list that immediately follows.',
          reference: 'RFC 4271 §4.3',
          byteRange: { start: 19, end: 21 },
        },
      ];

      if (withdrawnStart + withdrawnLen > msgBytes.length) {
        notes.push(
          `UPDATE Withdrawn Routes Length (${withdrawnLen}) exceeds available bytes (${msgBytes.length - withdrawnStart}).`,
        );
      }

      const decodedWithdrawn = decodePrefixList(
        msgBytes,
        withdrawnStart,
        withdrawnEnd,
        BGP_AFI.IPV4,
        ipv4AddPath,
        'update.withdrawn',
        'Withdrawn IPv4 route prefix',
      );
      notes.push(...decodedWithdrawn.notes);
      if (withdrawnEnd > withdrawnStart) {
        bodyChildren.push({
          id: 'update.withdrawn',
          label: 'Withdrawn Routes',
          value: decodedWithdrawn.prefixes.map((p) => p.prefix).join(', ') || '(malformed)',
          explanation: 'IPv4 prefixes that are no longer reachable via this peer and must be removed from the RIB.',
          reference: 'RFC 4271 §4.3',
          byteRange: { start: withdrawnStart, end: withdrawnEnd },
          children: decodedWithdrawn.nodes,
        });
      }

      let pathAttributes: BgpUpdateMessage['pathAttributes'] = [];
      let nlri: BgpUpdateMessage['nlri'] = [];
      let totalAttrLenOverride: number | undefined;

      if (withdrawnEnd + 2 > msgBytes.length) {
        notes.push('UPDATE is truncated before Total Path Attribute Length.');
        if (withdrawnEnd < msgBytes.length) {
          bodyChildren.push({
            id: 'update.truncatedAttrLen',
            label: 'Truncated Path Attribute Length',
            value: `0x${toHexString(msgBytes.slice(withdrawnEnd))}`,
            explanation: 'Fewer than 2 bytes remain for the Total Path Attribute Length field.',
            reference: 'RFC 4271 §4.3',
            byteRange: { start: withdrawnEnd, end: msgBytes.length },
          });
        }
      } else {
        const attrLenOffset = withdrawnEnd;
        const totalAttrLen = readUint16BE(msgBytes, attrLenOffset);
        const attrStart = attrLenOffset + 2;
        const attrEnd = Math.min(attrStart + totalAttrLen, msgBytes.length);

        if (attrStart + totalAttrLen > msgBytes.length) {
          notes.push(
            `UPDATE Total Path Attribute Length (${totalAttrLen}) exceeds remaining bytes (${msgBytes.length - attrStart}).`,
          );
          totalAttrLenOverride = totalAttrLen;
        }

        bodyChildren.push({
          id: 'update.pathAttrLength',
          label: 'Total Path Attribute Length',
          value: `${totalAttrLen} bytes`,
          explanation: 'Total length in octets of all Path Attributes in this UPDATE message.',
          reference: 'RFC 4271 §4.3',
          byteRange: { start: attrLenOffset, end: attrStart },
        });

        const decodedAttrs = decodePathAttributesSlice(
          msgBytes,
          attrStart,
          attrEnd,
          ctx,
          'update.pathAttrs',
        );
        pathAttributes = decodedAttrs.attributes;
        notes.push(...decodedAttrs.notes);

        if (attrEnd > attrStart) {
          bodyChildren.push({
            id: 'update.pathAttrs',
            label: 'Path Attributes',
            value: `${pathAttributes.length} ${pathAttributes.length === 1 ? 'attribute' : 'attributes'} (${attrEnd - attrStart} bytes)`,
            explanation: 'Properties describing the advertised route(s), shared by all prefixes packed into this UPDATE.',
            reference: 'RFC 4271 §4.3 / §5.1',
            byteRange: { start: attrStart, end: attrEnd },
            children: decodedAttrs.nodes,
          });
        }

        if (attrEnd < msgBytes.length) {
          const decodedNlri = decodePrefixList(
            msgBytes,
            attrEnd,
            msgBytes.length,
            BGP_AFI.IPV4,
            ipv4AddPath,
            'update.nlri',
            'Reachable IPv4 route prefix',
          );
          nlri = decodedNlri.prefixes;
          notes.push(...decodedNlri.notes);
          bodyChildren.push({
            id: 'update.nlri',
            label: 'Network Layer Reachability Information (NLRI)',
            value: nlri.map((p) => p.prefix).join(', ') || '(malformed)',
            explanation: 'IPv4 prefixes being announced as reachable using the Path Attributes above.',
            reference: 'RFC 4271 §4.3',
            byteRange: { start: attrEnd, end: msgBytes.length },
            children: decodedNlri.nodes,
          });
        }
      }

      const updateMsg: BgpUpdateMessage = {
        type: 'update',
        ...(markerOverride ? { markerHex: markerOverride } : {}),
        withdrawnRoutes: decodedWithdrawn.prefixes,
        pathAttributes,
        nlri,
        ...(withdrawnStart + withdrawnLen > msgBytes.length
          ? { withdrawnRoutesLengthOverride: withdrawnLen }
          : {}),
        ...(totalAttrLenOverride !== undefined
          ? { totalPathAttributeLengthOverride: totalAttrLenOverride }
          : {}),
      };

      const fallbackTree: DissectionNode = {
        id: 'bgp',
        label: 'BGP UPDATE Message',
        value: `${nlri.length} IPv4 NLRI, ${decodedWithdrawn.prefixes.length} withdrawn, ${pathAttributes.length} attrs`,
        explanation:
          'Advertises reachable routes with shared Path Attributes and/or withdraws previously advertised routes.',
        reference: 'RFC 4271 §4.3',
        byteRange: { start: 0, end: msgBytes.length },
        children: [headerNode, ...bodyChildren],
      };

      const tree = tryEncodeTree(updateMsg, fallbackTree);
      return { message: updateMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
    }

    case BGP_MESSAGE_TYPE.NOTIFICATION: {
      if (msgBytes.length < 21) {
        notes.push(
          `NOTIFICATION message at byte ${streamOffset} is too short (${msgBytes.length} bytes; minimum is 21).`,
        );
        const rawBody = msgBytes.slice(19);
        const fallbackMsg: BgpMessage = {
          type: 'unknown',
          ...(markerOverride ? { markerHex: markerOverride } : {}),
          typeCode,
          bodyHex: toHexString(rawBody),
        };
        const tree: DissectionNode = {
          id: 'bgp',
          label: 'BGP NOTIFICATION Message (Malformed)',
          value: `Truncated (${msgBytes.length} bytes)`,
          explanation: 'NOTIFICATION message is shorter than the 21-byte minimum required by RFC 4271 §4.5.',
          reference: 'RFC 4271 §4.5 / §6.1',
          byteRange: { start: 0, end: msgBytes.length },
          children: [
            headerNode,
            ...(rawBody.length > 0
              ? [
                  {
                    id: 'notification.truncated',
                    label: 'Truncated NOTIFICATION Body',
                    value: `0x${toHexString(rawBody)}`,
                    explanation: 'Partial NOTIFICATION body bytes before the message ended.',
                    reference: 'RFC 4271 §4.5',
                    byteRange: { start: 19, end: msgBytes.length },
                  },
                ]
              : []),
          ],
        };
        return { message: fallbackMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
      }

      const errorCode = msgBytes[19];
      const errorSubcode = msgBytes[20];
      const dataBytes = msgBytes.slice(21);
      const notifMsg: BgpNotificationMessage = {
        type: 'notification',
        ...(markerOverride ? { markerHex: markerOverride } : {}),
        errorCode,
        errorSubcode,
        dataHex: toHexString(dataBytes),
      };
      const errInfo = getNotificationErrorInfo(errorCode);
      const subInfo = getNotificationSubcodeInfo(errorCode, errorSubcode);
      const fallbackTree: DissectionNode = {
        id: 'bgp',
        label: 'BGP NOTIFICATION Message',
        value: `${errorCode}/${errorSubcode}: ${errInfo.name} — ${subInfo.name}`,
        explanation:
          'Sent when an error or administrative close occurs; the TCP BGP session is closed immediately afterward.',
        reference: subInfo.reference,
        byteRange: { start: 0, end: msgBytes.length },
        children: [
          headerNode,
          {
            id: 'notification.errorCode',
            label: 'Error Code',
            value: `${errorCode} (${errInfo.name})`,
            explanation: errInfo.explanation,
            reference: errInfo.reference,
            byteRange: { start: 19, end: 20 },
          },
          {
            id: 'notification.errorSubcode',
            label: 'Error Subcode',
            value: `${errorSubcode} (${subInfo.name})`,
            explanation: subInfo.explanation,
            reference: subInfo.reference,
            byteRange: { start: 20, end: 21 },
          },
          ...(dataBytes.length > 0
            ? [
                {
                  id: 'notification.data',
                  label: 'Data',
                  value: `0x${toHexString(dataBytes)}`,
                  explanation: 'Diagnostic data accompanying the NOTIFICATION.',
                  reference: 'RFC 4271 §4.5',
                  byteRange: { start: 21, end: msgBytes.length },
                },
              ]
            : []),
        ],
      };
      const tree = tryEncodeTree(notifMsg, fallbackTree);
      return { message: notifMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
    }

    case BGP_MESSAGE_TYPE.KEEPALIVE: {
      if (msgBytes.length > BGP_HEADER_LENGTH) {
        notes.push(
          `KEEPALIVE at byte ${streamOffset} has unexpected body of ${msgBytes.length - BGP_HEADER_LENGTH} byte(s) (RFC 4271 §4.4 requires length 19).`,
        );
      }
      const keepaliveMsg: BgpMessage =
        msgBytes.length === BGP_HEADER_LENGTH
          ? {
              type: 'keepalive',
              ...(markerOverride ? { markerHex: markerOverride } : {}),
            }
          : {
              type: 'unknown',
              ...(markerOverride ? { markerHex: markerOverride } : {}),
              typeCode,
              bodyHex: toHexString(msgBytes.slice(19)),
            };
      const fallbackTree: DissectionNode = {
        id: 'bgp',
        label: 'BGP KEEPALIVE Message',
        value:
          msgBytes.length === BGP_HEADER_LENGTH
            ? '19-byte header only'
            : `${msgBytes.length} bytes (unexpected trailing body)`,
        explanation:
          'Periodic heartbeat confirming the peer is alive and resetting the Hold Timer; RFC 4271 §4.4 specifies a 19-byte message with no body.',
        reference: 'RFC 4271 §4.4',
        byteRange: { start: 0, end: msgBytes.length },
        children: [
          headerNode,
          ...(msgBytes.length > BGP_HEADER_LENGTH
            ? [
                {
                  id: 'keepalive.extra',
                  label: 'Unexpected Body',
                  value: `0x${toHexString(msgBytes.slice(19))}`,
                  explanation: 'KEEPALIVE messages must not contain a body.',
                  reference: 'RFC 4271 §4.4 / §6.1',
                  byteRange: { start: 19, end: msgBytes.length },
                },
              ]
            : []),
        ],
      };
      const tree =
        msgBytes.length > BGP_HEADER_LENGTH
          ? fallbackTree
          : tryEncodeTree(keepaliveMsg, fallbackTree);
      return { message: keepaliveMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
    }

    case BGP_MESSAGE_TYPE.ROUTE_REFRESH: {
      if (msgBytes.length !== 23) {
        notes.push(
          `ROUTE-REFRESH at byte ${streamOffset} has length ${msgBytes.length} (expected 23 per RFC 2918 §3 / RFC 7313 §5).`,
        );
      }
      if (msgBytes.length < 23) {
        const rawBody = msgBytes.slice(19);
        const fallbackMsg: BgpMessage = {
          type: 'unknown',
          ...(markerOverride ? { markerHex: markerOverride } : {}),
          typeCode,
          bodyHex: toHexString(rawBody),
        };
        const tree: DissectionNode = {
          id: 'bgp',
          label: 'BGP ROUTE-REFRESH Message (Malformed)',
          value: `Truncated (${msgBytes.length} bytes)`,
          explanation: 'ROUTE-REFRESH message must be exactly 23 bytes.',
          reference: 'RFC 2918 §3 / RFC 7313 §5',
          byteRange: { start: 0, end: msgBytes.length },
          children: [
            headerNode,
            ...(rawBody.length > 0
              ? [
                  {
                    id: 'routeRefresh.truncated',
                    label: 'Truncated ROUTE-REFRESH Body',
                    value: `0x${toHexString(rawBody)}`,
                    explanation: 'Partial ROUTE-REFRESH body bytes before the message ended.',
                    reference: 'RFC 2918 §3',
                    byteRange: { start: 19, end: msgBytes.length },
                  },
                ]
              : []),
          ],
        };
        return { message: fallbackMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
      }

      const afi = readUint16BE(msgBytes, 19);
      const subtype = msgBytes[21];
      const safi = msgBytes[22];
      const rrMsg: BgpRouteRefreshMessage = {
        type: 'routeRefresh',
        ...(markerOverride ? { markerHex: markerOverride } : {}),
        afi,
        subtype,
        safi,
      };
      const subInfo = getRouteRefreshSubtypeInfo(subtype);
      const fallbackTree: DissectionNode = {
        id: 'bgp',
        label: 'BGP ROUTE-REFRESH Message',
        value: `${subInfo.name} for ${formatAfiSafi(afi, safi)}`,
        explanation: 'Requests the peer to re-advertise routes for an AFI/SAFI without resetting the session.',
        reference: subtype === 0 ? 'RFC 2918 §3' : 'RFC 7313 §3.2',
        byteRange: { start: 0, end: msgBytes.length },
        children: [
          headerNode,
          {
            id: 'routeRefresh.afi',
            label: 'AFI',
            value: `${afi} (${getAfiName(afi)})`,
            explanation: 'Address Family Identifier being refreshed.',
            reference: 'RFC 2918 §3',
            byteRange: { start: 19, end: 21 },
          },
          {
            id: 'routeRefresh.subtype',
            label: 'Subtype (Reserved)',
            value: `${subtype} (${subInfo.name})`,
            explanation: subInfo.explanation,
            reference: subInfo.reference,
            byteRange: { start: 21, end: 22 },
          },
          {
            id: 'routeRefresh.safi',
            label: 'SAFI',
            value: `${safi} (${getSafiName(safi)})`,
            explanation: 'Subsequent Address Family Identifier being refreshed.',
            reference: 'RFC 2918 §3',
            byteRange: { start: 22, end: 23 },
          },
          ...(msgBytes.length > 23
            ? [
                {
                  id: 'routeRefresh.trailing',
                  label: 'Trailing Bytes',
                  value: `0x${toHexString(msgBytes.slice(23))}`,
                  explanation: 'Extra bytes after the 4-byte ROUTE-REFRESH body.',
                  reference: 'RFC 7313 §5',
                  byteRange: { start: 23, end: msgBytes.length },
                },
              ]
            : []),
        ],
      };
      const tree = tryEncodeTree(rrMsg, fallbackTree);
      return { message: rrMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
    }

    default: {
      notes.push(`Unrecognized BGP message type ${typeCode} at byte ${streamOffset}.`);
      const bodyBytes = msgBytes.slice(19);
      const unknownMsg: BgpMessage = {
        type: 'unknown',
        ...(markerOverride ? { markerHex: markerOverride } : {}),
        typeCode,
        bodyHex: toHexString(bodyBytes),
      };
      const fallbackTree: DissectionNode = {
        id: 'bgp',
        label: `BGP Unknown Message (Type ${typeCode})`,
        value: `${msgBytes.length} bytes`,
        explanation: 'BGP message with an unrecognized message type code.',
        reference: 'RFC 4271 §4.1 / §6.1',
        byteRange: { start: 0, end: msgBytes.length },
        children: [
          headerNode,
          ...(bodyBytes.length > 0
            ? [
                {
                  id: 'unknown.body',
                  label: 'Message Body (Raw)',
                  value: `0x${toHexString(bodyBytes)}`,
                  explanation: 'Opaque body bytes for an unrecognized BGP message type.',
                  reference: 'RFC 4271 §4.1',
                  byteRange: { start: 19, end: msgBytes.length },
                },
              ]
            : []),
        ],
      };
      const tree = tryEncodeTree(unknownMsg, fallbackTree);
      return { message: unknownMsg, bytes: msgBytes, tree, offset: streamOffset, notes };
    }
  }
}

/**
 * Decodes one or more back-to-back raw BGP messages from a byte buffer.
 * Never throws; returns partial results, diagnostic notes, and any unparsed tail bytes.
 */
export function decodeBgpMessages(
  bytes: Uint8Array,
  ctx: BgpCodecContext = DEFAULT_BGP_CODEC_CONTEXT,
): BgpDecodeResult {
  const messages: DecodedBgpMessage[] = [];
  const notes: string[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    const remaining = bytes.length - offset;
    if (remaining < BGP_HEADER_LENGTH) {
      notes.push(
        `Stopped at byte ${offset}: need at least ${BGP_HEADER_LENGTH} bytes for a BGP header, but only ${remaining} byte(s) remain.`,
      );
      return {
        messages,
        notes,
        unparsedBytes: bytes.slice(offset),
        unparsedOffset: offset,
      };
    }

    const declaredLength = readUint16BE(bytes, offset + 16);
    if (declaredLength < BGP_HEADER_LENGTH) {
      notes.push(
        `Stopped at byte ${offset}: BGP header declares invalid length ${declaredLength} (minimum is ${BGP_HEADER_LENGTH}).`,
      );
      return {
        messages,
        notes,
        unparsedBytes: bytes.slice(offset),
        unparsedOffset: offset,
      };
    }

    if (declaredLength > remaining) {
      notes.push(
        `Stopped at byte ${offset}: BGP header declares length ${declaredLength}, but only ${remaining} byte(s) remain (truncated by ${declaredLength - remaining} bytes).`,
      );
      return {
        messages,
        notes,
        unparsedBytes: bytes.slice(offset),
        unparsedOffset: offset,
      };
    }

    const msgSlice = bytes.slice(offset, offset + declaredLength);
    const decoded = decodeSingleMessage(msgSlice, offset, ctx);
    messages.push(decoded);
    notes.push(...decoded.notes);
    offset += declaredLength;
  }

  return {
    messages,
    notes,
    unparsedBytes: new Uint8Array(0),
    unparsedOffset: offset,
  };
}

/**
 * Parses a raw hex stream or hex dump and decodes one or more BGP messages.
 * Never throws on invalid hex or malformed BGP bytes.
 */
export function decodeBgpHex(
  text: string,
  ctx: BgpCodecContext = DEFAULT_BGP_CODEC_CONTEXT,
): BgpDecodeResult {
  const parsed = parseHexOrDump(text);
  if (!parsed.ok) {
    return {
      messages: [],
      notes: [parsed.error],
      unparsedBytes: new Uint8Array(0),
      unparsedOffset: 0,
    };
  }
  if (parsed.value.length === 0) {
    return {
      messages: [],
      notes: ['Input is empty. Paste one or more BGP messages starting with the 16-byte 0xff Marker.'],
      unparsedBytes: new Uint8Array(0),
      unparsedOffset: 0,
    };
  }
  return decodeBgpMessages(parsed.value, ctx);
}
