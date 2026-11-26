import {
  concatBytes,
  parseHexBytes,
  parseIPv4,
  toHexString,
  writeUint16BE,
} from '../bytes';
import { err, ok, type Result } from '../result';
import { encodePathAttribute } from './attributes';
import { encodeCapability } from './capabilities';
import { buildCommonHeaderNode, isUint16, isUint32, isUint8 } from './common';
import { encodePrefixList } from './prefix';
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
  type AfiSafi,
  type BgpCodecContext,
  type BgpMessage,
  type BgpOpenMessage,
  type BgpOptionalParameter,
  type BgpUpdateMessage,
  type DissectionNode,
  type EncodedBgpMessage,
} from './types';

export function resolveOpenMyAs(msg: BgpOpenMessage): number {
  if (msg.myAsOverride !== undefined) {
    return msg.myAsOverride;
  }
  return msg.asn <= 0xffff ? msg.asn : BGP_AS_TRANS;
}

export function createEndOfRib(
  afi: number = BGP_AFI.IPV4,
  safi: number = BGP_SAFI.UNICAST,
): BgpUpdateMessage {
  if (afi === BGP_AFI.IPV4 && safi === BGP_SAFI.UNICAST) {
    return {
      type: 'update',
      withdrawnRoutes: [],
      pathAttributes: [],
      nlri: [],
    };
  }
  return {
    type: 'update',
    withdrawnRoutes: [],
    pathAttributes: [
      {
        kind: 'mpUnreachNlri',
        afi,
        safi,
        withdrawnRoutes: [],
      },
    ],
    nlri: [],
  };
}

export function isEndOfRib(msg: BgpMessage): AfiSafi | null {
  if (msg.type !== 'update') return null;
  if (msg.withdrawnRoutes.length === 0 && msg.nlri.length === 0) {
    if (msg.pathAttributes.length === 0) {
      return { afi: BGP_AFI.IPV4, safi: BGP_SAFI.UNICAST };
    }
    if (
      msg.pathAttributes.length === 1 &&
      msg.pathAttributes[0].kind === 'mpUnreachNlri' &&
      msg.pathAttributes[0].withdrawnRoutes.length === 0
    ) {
      return {
        afi: msg.pathAttributes[0].afi,
        safi: msg.pathAttributes[0].safi,
      };
    }
  }
  return null;
}

export function encodeBgpMessage(
  msg: BgpMessage,
  ctx: BgpCodecContext = DEFAULT_BGP_CODEC_CONTEXT,
): Result<EncodedBgpMessage> {
  const warnings: string[] = [];

  // 1. Marker (16 bytes)
  let markerBytes: Uint8Array;
  if (msg.markerHex !== undefined) {
    const parsedMarker = parseHexBytes(msg.markerHex);
    if (!parsedMarker.ok) return err(`Invalid markerHex: ${parsedMarker.error}`);
    if (parsedMarker.value.length !== BGP_MARKER_LENGTH) {
      return err(`BGP Marker must be exactly 16 bytes (got ${parsedMarker.value.length}).`);
    }
    markerBytes = parsedMarker.value;
    if (!markerBytes.every((b) => b === 0xff)) {
      warnings.push('BGP Marker is not all 0xff; peers will send NOTIFICATION 1/1 (Connection Not Synchronized).');
    }
  } else {
    markerBytes = new Uint8Array(BGP_MARKER_LENGTH).fill(0xff);
  }

  let typeCode: number;
  let bodyBytes: Uint8Array;
  let rootLabel: string;
  let rootValue: string;
  let rootExplanation: string;
  let rootReference: string;
  const bodyNodes: DissectionNode[] = [];

  switch (msg.type) {
    case 'open': {
      typeCode = BGP_MESSAGE_TYPE.OPEN;
      if (!isUint8(msg.version)) {
        return err(`OPEN Version must be 0-255 (got ${msg.version}).`);
      }
      if (!isUint32(msg.asn)) {
        return err(`OPEN ASN must be a 32-bit unsigned integer (got ${msg.asn}).`);
      }
      const myAs = resolveOpenMyAs(msg);
      if (!isUint16(myAs)) {
        return err(`OPEN My AS must be 0-65535 (got ${myAs}).`);
      }
      if (!isUint16(msg.holdTime)) {
        return err(`OPEN Hold Time must be 0-65535 (got ${msg.holdTime}).`);
      }
      if (msg.holdTime === 1 || msg.holdTime === 2) {
        warnings.push('Hold Time must be 0 or >= 3 seconds per RFC 4271 §4.2.');
      }
      const routerIdRes = parseIPv4(msg.bgpIdentifier);
      if (!routerIdRes.ok) {
        return err(`OPEN BGP Identifier invalid IPv4: ${routerIdRes.error}`);
      }

      const fixedBody = new Uint8Array(10);
      fixedBody[0] = msg.version;
      writeUint16BE(fixedBody, 1, myAs);
      writeUint16BE(fixedBody, 3, msg.holdTime);
      fixedBody.set(routerIdRes.value, 5);
      // fixedBody[9] is Optional Parameters Length, filled after encoding optional params

      const optParamChunks: Uint8Array[] = [];
      const optParamNodes: DissectionNode[] = [];
      let optCursor = BGP_HEADER_LENGTH + 10; // byte 29

      const effectiveOptParams: BgpOptionalParameter[] = [];
      if (msg.optionalParameters !== undefined) {
        effectiveOptParams.push(...msg.optionalParameters);
      } else {
        if (msg.capabilities.length > 0) {
          // Pack capabilities into one (or more, if > 255B) Optional Parameter Type 2 containers (RFC 5492 §4)
          let currentGroup: typeof msg.capabilities[number][] = [];
          let currentLen = 0;
          for (let i = 0; i < msg.capabilities.length; i++) {
            const cap = msg.capabilities[i];
            const probe = encodeCapability(cap, 0, `optParams.cap[${i}]`);
            if (!probe.ok) return probe;
            if (currentGroup.length > 0 && currentLen + probe.value.bytes.length > 255) {
              effectiveOptParams.push({ kind: 'capabilities', capabilities: currentGroup });
              currentGroup = [];
              currentLen = 0;
            }
            currentGroup.push(cap);
            currentLen += probe.value.bytes.length;
          }
          if (currentGroup.length > 0) {
            effectiveOptParams.push({
              kind: 'capabilities',
              capabilities: currentGroup,
              ...(msg.capParamLengthOverride !== undefined && effectiveOptParams.length === 0
                ? { lengthOverride: msg.capParamLengthOverride }
                : {}),
            });
          }
        }
        if (msg.extraOptionalParameters) {
          for (const extra of msg.extraOptionalParameters) {
            effectiveOptParams.push({
              kind: 'raw',
              type: extra.type,
              dataHex: extra.dataHex,
              ...(extra.lengthOverride !== undefined ? { lengthOverride: extra.lengthOverride } : {}),
            });
          }
        }
      }

      for (let pIdx = 0; pIdx < effectiveOptParams.length; pIdx++) {
        const param = effectiveOptParams[pIdx];
        const pStart = optCursor;

        if (param.kind === 'capabilities') {
          let capCursor = pStart + 2;
          const capNodes: DissectionNode[] = [];
          const capByteParts: Uint8Array[] = [];

          for (let cIdx = 0; cIdx < param.capabilities.length; cIdx++) {
            const encoded = encodeCapability(
              param.capabilities[cIdx],
              capCursor,
              `open.optParams[${pIdx}].cap[${cIdx}]`,
            );
            if (!encoded.ok) return encoded;
            capNodes.push(encoded.value.node);
            capByteParts.push(encoded.value.bytes);
            capCursor += encoded.value.bytes.length;
          }

          const capsBytes = concatBytes(...capByteParts);
          const wireCapParamLen = param.lengthOverride ?? capsBytes.length;
          if (!isUint8(wireCapParamLen) || capsBytes.length > 255) {
            return err(
              `Capabilities Optional Parameter length must be 0-255 (got ${wireCapParamLen}).`,
            );
          }

          const paramBuf = new Uint8Array(2 + capsBytes.length);
          paramBuf[0] = 2; // Optional Parameter Type 2 = Capabilities
          paramBuf[1] = wireCapParamLen;
          paramBuf.set(capsBytes, 2);

          optParamChunks.push(paramBuf);
          optParamNodes.push({
            id: `open.optParams[${pIdx}]`,
            label: 'Optional Parameter: Capabilities (Type 2)',
            value: `${param.capabilities.length} ${param.capabilities.length === 1 ? 'capability' : 'capabilities'} (${capsBytes.length} bytes)`,
            explanation:
              'Optional Parameter Type 2 carries BGP capability TLVs so peers can negotiate features like MP-BGP, 4-octet AS, and Route Refresh.',
            reference: 'RFC 5492 §4',
            byteRange: { start: pStart, end: pStart + paramBuf.length },
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
                value:
                  param.lengthOverride !== undefined && param.lengthOverride !== capsBytes.length
                    ? `${wireCapParamLen} bytes (manual override; actual ${capsBytes.length} bytes)`
                    : `${wireCapParamLen} bytes`,
                explanation:
                  'Total length in octets of the capability TLVs inside this Optional Parameter.',
                reference: 'RFC 5492 §4',
                byteRange: { start: pStart + 1, end: pStart + 2 },
              },
              ...capNodes,
            ],
          });
          optCursor += paramBuf.length;
        } else {
          if (!isUint8(param.type)) {
            return err(`Optional parameter #${pIdx + 1} type must be 0-255.`);
          }
          const dataRes = parseHexBytes(param.dataHex);
          if (!dataRes.ok) {
            return err(`Optional parameter #${pIdx + 1} dataHex: ${dataRes.error}`);
          }
          const wireLen = param.lengthOverride ?? dataRes.value.length;
          if (!isUint8(wireLen) || dataRes.value.length > 255) {
            return err(`Optional parameter #${pIdx + 1} length must be 0-255.`);
          }
          const pBuf = new Uint8Array(2 + dataRes.value.length);
          pBuf[0] = param.type;
          pBuf[1] = wireLen;
          pBuf.set(dataRes.value, 2);
          optParamChunks.push(pBuf);
          optParamNodes.push({
            id: `open.optParams[${pIdx}]`,
            label: `Optional Parameter (Type ${param.type})`,
            value: dataRes.value.length === 0 ? '(empty)' : `0x${toHexString(dataRes.value)}`,
            explanation: 'Non-Capabilities Optional Parameter carried in the BGP OPEN message.',
            reference: 'RFC 4271 §4.2',
            byteRange: { start: pStart, end: pStart + pBuf.length },
            children: [
              {
                id: `open.optParams[${pIdx}].type`,
                label: 'Parameter Type',
                value: String(param.type),
                explanation: '1-byte Optional Parameter type code.',
                reference: 'RFC 4271 §4.2',
                byteRange: { start: pStart, end: pStart + 1 },
              },
              {
                id: `open.optParams[${pIdx}].length`,
                label: 'Parameter Length',
                value:
                  param.lengthOverride !== undefined &&
                  param.lengthOverride !== dataRes.value.length
                    ? `${wireLen} bytes (manual override; actual ${dataRes.value.length} bytes)`
                    : `${wireLen} bytes`,
                explanation: 'Length of this Optional Parameter value in octets.',
                reference: 'RFC 4271 §4.2',
                byteRange: { start: pStart + 1, end: pStart + 2 },
              },
              ...(dataRes.value.length > 0
                ? [
                    {
                      id: `open.optParams[${pIdx}].value`,
                      label: 'Parameter Value',
                      value: `0x${toHexString(dataRes.value)}`,
                      explanation: 'Opaque Optional Parameter value bytes.',
                      reference: 'RFC 4271 §4.2',
                      byteRange: { start: pStart + 2, end: pStart + pBuf.length },
                    },
                  ]
                : []),
            ],
          });
          optCursor += pBuf.length;
        }
      }

      const optParamsBytes = concatBytes(...optParamChunks);
      const wireOptParamLen = msg.optParamLengthOverride ?? optParamsBytes.length;
      if (!isUint8(wireOptParamLen)) {
        return err(`OPEN Optional Parameters Length must be 0-255 (got ${wireOptParamLen}).`);
      }
      fixedBody[9] = wireOptParamLen;
      bodyBytes = concatBytes(fixedBody, optParamsBytes);

      const usedAsTrans = msg.myAsOverride === undefined && msg.asn > 0xffff;
      const myAsValueText = usedAsTrans
        ? `${myAs} (AS_TRANS for 4-octet AS ${msg.asn})`
        : myAs === BGP_AS_TRANS
          ? `${myAs} (AS_TRANS)`
          : String(myAs);
      const myAsExplanation = usedAsTrans
        ? `Because AS ${msg.asn} does not fit in this 16-bit header field, RFC 6793 places AS_TRANS (23456) here and carries the real 32-bit ASN in Capability 65.`
        : '16-bit Autonomous System Number of the sending BGP speaker (or AS_TRANS 23456 when the speaker has a 4-octet ASN > 65535).';

      bodyNodes.push(
        {
          id: 'open.version',
          label: 'Version',
          value: String(msg.version),
          explanation: 'BGP protocol version number. Modern BGP always uses version 4.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 19, end: 20 },
        },
        {
          id: 'open.myAs',
          label: 'My Autonomous System',
          value: myAsValueText,
          explanation: myAsExplanation,
          reference: usedAsTrans || myAs === BGP_AS_TRANS ? 'RFC 4271 §4.2 / RFC 6793 §3' : 'RFC 4271 §4.2',
          byteRange: { start: 20, end: 22 },
        },
        {
          id: 'open.holdTime',
          label: 'Hold Time',
          value: msg.holdTime === 0 ? '0 s (Hold Timer disabled)' : `${msg.holdTime} s`,
          explanation:
            'Proposed maximum seconds allowed between successive KEEPALIVE or UPDATE messages; peers negotiate the smaller of their two values.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 22, end: 24 },
        },
        {
          id: 'open.bgpIdentifier',
          label: 'BGP Identifier',
          value: msg.bgpIdentifier,
          explanation: '32-bit IPv4-formatted Router ID uniquely identifying this BGP speaker within its AS.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 24, end: 28 },
        },
        {
          id: 'open.optParamLength',
          label: 'Optional Parameters Length',
          value:
            msg.optParamLengthOverride !== undefined &&
            msg.optParamLengthOverride !== optParamsBytes.length
              ? `${wireOptParamLen} bytes (manual override; actual ${optParamsBytes.length} bytes)`
              : `${wireOptParamLen} bytes`,
          explanation: 'Total length in octets of the Optional Parameters field that follows.',
          reference: 'RFC 4271 §4.2',
          byteRange: { start: 28, end: 29 },
        },
      );

      if (optParamsBytes.length > 0) {
        bodyNodes.push({
          id: 'open.optParams',
          label: 'Optional Parameters',
          value: `${optParamNodes.length} ${optParamNodes.length === 1 ? 'parameter' : 'parameters'} (${optParamsBytes.length} bytes)`,
          explanation: 'TLV-encoded Optional Parameters, primarily carrying BGP Capabilities (Type 2).',
          reference: 'RFC 4271 §4.2 / RFC 5492 §4',
          byteRange: { start: 29, end: 29 + optParamsBytes.length },
          children: optParamNodes,
        });
      }

      rootLabel = 'BGP OPEN Message';
      rootValue = `AS ${msg.asn}, Hold ${msg.holdTime}s, Router ID ${msg.bgpIdentifier}, ${msg.capabilities.length} ${msg.capabilities.length === 1 ? 'cap' : 'caps'}`;
      rootExplanation =
        'First BGP message sent after TCP connects. Advertises the speaker’s ASN, Hold Time, Router ID, and supported capabilities.';
      rootReference = 'RFC 4271 §4.2';
      break;
    }

    case 'update': {
      typeCode = BGP_MESSAGE_TYPE.UPDATE;
      const ipv4AddPath = hasAddPathForAfiSafi(ctx, BGP_AFI.IPV4, BGP_SAFI.UNICAST);

      const withdrawnStart = BGP_HEADER_LENGTH + 2; // byte 21
      const withdrawnRes = encodePrefixList(
        msg.withdrawnRoutes,
        BGP_AFI.IPV4,
        ipv4AddPath,
        withdrawnStart,
        'update.withdrawn',
        'Withdrawn IPv4 route prefix',
      );
      if (!withdrawnRes.ok) return withdrawnRes;
      warnings.push(...withdrawnRes.value.warnings);
      const withdrawnBytes = withdrawnRes.value.bytes;

      const wireWithdrawnLen = msg.withdrawnRoutesLengthOverride ?? withdrawnBytes.length;
      if (!isUint16(wireWithdrawnLen)) {
        return err(`Withdrawn Routes Length must be 0-65535 (got ${wireWithdrawnLen}).`);
      }

      const pathAttrLenOffset = withdrawnStart + withdrawnBytes.length;
      const pathAttrStart = pathAttrLenOffset + 2;
      let attrCursor = pathAttrStart;
      const attrByteParts: Uint8Array[] = [];
      const attrNodes: DissectionNode[] = [];

      for (let i = 0; i < msg.pathAttributes.length; i++) {
        const encodedAttr = encodePathAttribute(
          msg.pathAttributes[i],
          ctx,
          attrCursor,
          `update.pathAttrs[${i}]`,
        );
        if (!encodedAttr.ok) return encodedAttr;
        attrByteParts.push(encodedAttr.value.bytes);
        attrNodes.push(encodedAttr.value.node);
        attrCursor += encodedAttr.value.bytes.length;
      }
      const attrBytes = concatBytes(...attrByteParts);

      const wireAttrLen = msg.totalPathAttributeLengthOverride ?? attrBytes.length;
      if (!isUint16(wireAttrLen)) {
        return err(`Total Path Attribute Length must be 0-65535 (got ${wireAttrLen}).`);
      }

      const nlriStart = pathAttrStart + attrBytes.length;
      const nlriRes = encodePrefixList(
        msg.nlri,
        BGP_AFI.IPV4,
        ipv4AddPath,
        nlriStart,
        'update.nlri',
        'Reachable IPv4 route prefix',
      );
      if (!nlriRes.ok) return nlriRes;
      warnings.push(...nlriRes.value.warnings);
      const nlriBytes = nlriRes.value.bytes;

      const withdrawnLenBuf = new Uint8Array(2);
      writeUint16BE(withdrawnLenBuf, 0, wireWithdrawnLen);
      const attrLenBuf = new Uint8Array(2);
      writeUint16BE(attrLenBuf, 0, wireAttrLen);

      bodyBytes = concatBytes(
        withdrawnLenBuf,
        withdrawnBytes,
        attrLenBuf,
        attrBytes,
        nlriBytes,
      );

      bodyNodes.push({
        id: 'update.withdrawnLength',
        label: 'Withdrawn Routes Length',
        value:
          msg.withdrawnRoutesLengthOverride !== undefined &&
          msg.withdrawnRoutesLengthOverride !== withdrawnBytes.length
            ? `${wireWithdrawnLen} bytes (manual override; actual ${withdrawnBytes.length} bytes)`
            : `${wireWithdrawnLen} bytes`,
        explanation: 'Total length in octets of the IPv4 Withdrawn Routes list that immediately follows.',
        reference: 'RFC 4271 §4.3',
        byteRange: { start: 19, end: 21 },
      });

      if (withdrawnBytes.length > 0) {
        bodyNodes.push({
          id: 'update.withdrawn',
          label: 'Withdrawn Routes',
          value: msg.withdrawnRoutes.map((p) => p.prefix).join(', '),
          explanation: 'IPv4 prefixes that are no longer reachable via this peer and must be removed from the RIB.',
          reference: 'RFC 4271 §4.3',
          byteRange: { start: withdrawnStart, end: withdrawnStart + withdrawnBytes.length },
          children: withdrawnRes.value.nodes,
        });
      }

      bodyNodes.push({
        id: 'update.pathAttrLength',
        label: 'Total Path Attribute Length',
        value:
          msg.totalPathAttributeLengthOverride !== undefined &&
          msg.totalPathAttributeLengthOverride !== attrBytes.length
            ? `${wireAttrLen} bytes (manual override; actual ${attrBytes.length} bytes)`
            : `${wireAttrLen} bytes`,
        explanation: 'Total length in octets of all Path Attributes in this UPDATE message.',
        reference: 'RFC 4271 §4.3',
        byteRange: { start: pathAttrLenOffset, end: pathAttrStart },
      });

      if (attrBytes.length > 0) {
        bodyNodes.push({
          id: 'update.pathAttrs',
          label: 'Path Attributes',
          value: `${msg.pathAttributes.length} ${msg.pathAttributes.length === 1 ? 'attribute' : 'attributes'} (${attrBytes.length} bytes)`,
          explanation: 'Properties describing the advertised route(s), shared by all prefixes packed into this UPDATE.',
          reference: 'RFC 4271 §4.3 / §5.1',
          byteRange: { start: pathAttrStart, end: pathAttrStart + attrBytes.length },
          children: attrNodes,
        });
      }

      if (nlriBytes.length > 0) {
        bodyNodes.push({
          id: 'update.nlri',
          label: 'Network Layer Reachability Information (NLRI)',
          value: msg.nlri.map((p) => p.prefix).join(', '),
          explanation: 'IPv4 prefixes being announced as reachable using the Path Attributes above.',
          reference: 'RFC 4271 §4.3',
          byteRange: { start: nlriStart, end: nlriStart + nlriBytes.length },
          children: nlriRes.value.nodes,
        });
      }

      const eor = isEndOfRib(msg);
      rootLabel = eor ? 'BGP UPDATE Message (End-of-RIB)' : 'BGP UPDATE Message';
      rootValue = eor
        ? `End-of-RIB for ${formatAfiSafi(eor.afi, eor.safi)}`
        : `${msg.nlri.length} IPv4 NLRI, ${msg.withdrawnRoutes.length} withdrawn, ${msg.pathAttributes.length} attrs`;
      rootExplanation = eor
        ? 'An empty UPDATE (or empty MP_UNREACH_NLRI) serving as the End-of-RIB marker indicating all initial routes for this address family have been sent.'
        : 'Advertises reachable routes with shared Path Attributes and/or withdraws previously advertised routes.';
      rootReference = eor ? 'RFC 4724 §2' : 'RFC 4271 §4.3';
      break;
    }

    case 'notification': {
      typeCode = BGP_MESSAGE_TYPE.NOTIFICATION;
      if (!isUint8(msg.errorCode)) {
        return err(`NOTIFICATION Error Code must be 0-255 (got ${msg.errorCode}).`);
      }
      if (!isUint8(msg.errorSubcode)) {
        return err(`NOTIFICATION Error Subcode must be 0-255 (got ${msg.errorSubcode}).`);
      }
      const dataRes = parseHexBytes(msg.dataHex);
      if (!dataRes.ok) {
        return err(`NOTIFICATION dataHex invalid: ${dataRes.error}`);
      }
      const dataBytes = dataRes.value;
      bodyBytes = new Uint8Array(2 + dataBytes.length);
      bodyBytes[0] = msg.errorCode;
      bodyBytes[1] = msg.errorSubcode;
      bodyBytes.set(dataBytes, 2);

      const errInfo = getNotificationErrorInfo(msg.errorCode);
      const subInfo = getNotificationSubcodeInfo(msg.errorCode, msg.errorSubcode);

      bodyNodes.push(
        {
          id: 'notification.errorCode',
          label: 'Error Code',
          value: `${msg.errorCode} (${errInfo.name})`,
          explanation: errInfo.explanation,
          reference: errInfo.reference,
          byteRange: { start: 19, end: 20 },
        },
        {
          id: 'notification.errorSubcode',
          label: 'Error Subcode',
          value: `${msg.errorSubcode} (${subInfo.name})`,
          explanation: subInfo.explanation,
          reference: subInfo.reference,
          byteRange: { start: 20, end: 21 },
        },
      );

      if (dataBytes.length > 0) {
        bodyNodes.push({
          id: 'notification.data',
          label: 'Data',
          value: `0x${toHexString(dataBytes)} (${dataBytes.length} ${dataBytes.length === 1 ? 'byte' : 'bytes'})`,
          explanation: 'Diagnostic data explaining the error (for example, the offending attribute or shutdown communication).',
          reference: 'RFC 4271 §4.5',
          byteRange: { start: 21, end: 21 + dataBytes.length },
        });
      }

      rootLabel = 'BGP NOTIFICATION Message';
      rootValue = `${msg.errorCode}/${msg.errorSubcode}: ${errInfo.name} — ${subInfo.name}`;
      rootExplanation =
        'Sent when an error or administrative close occurs; the TCP BGP session is closed immediately afterward.';
      rootReference = subInfo.reference;
      break;
    }

    case 'keepalive': {
      typeCode = BGP_MESSAGE_TYPE.KEEPALIVE;
      bodyBytes = new Uint8Array(0);
      rootLabel = 'BGP KEEPALIVE Message';
      rootValue = '19-byte header only';
      rootExplanation =
        'Periodic heartbeat (header only, no body) confirming the peer is alive and resetting the Hold Timer; also confirms OPEN acceptance.';
      rootReference = 'RFC 4271 §4.4';
      break;
    }

    case 'routeRefresh': {
      typeCode = BGP_MESSAGE_TYPE.ROUTE_REFRESH;
      if (!isUint16(msg.afi) || !isUint8(msg.subtype) || !isUint8(msg.safi)) {
        return err(`ROUTE-REFRESH invalid AFI/Subtype/SAFI (${msg.afi}/${msg.subtype}/${msg.safi}).`);
      }
      bodyBytes = new Uint8Array(4);
      writeUint16BE(bodyBytes, 0, msg.afi);
      bodyBytes[2] = msg.subtype;
      bodyBytes[3] = msg.safi;

      const subInfo = getRouteRefreshSubtypeInfo(msg.subtype);
      bodyNodes.push(
        {
          id: 'routeRefresh.afi',
          label: 'AFI',
          value: `${msg.afi} (${getAfiName(msg.afi)})`,
          explanation: 'Address Family Identifier being refreshed.',
          reference: 'RFC 2918 §3',
          byteRange: { start: 19, end: 21 },
        },
        {
          id: 'routeRefresh.subtype',
          label: 'Subtype (Reserved)',
          value: `${msg.subtype} (${subInfo.name})`,
          explanation: subInfo.explanation,
          reference: subInfo.reference,
          byteRange: { start: 21, end: 22 },
        },
        {
          id: 'routeRefresh.safi',
          label: 'SAFI',
          value: `${msg.safi} (${getSafiName(msg.safi)})`,
          explanation: 'Subsequent Address Family Identifier being refreshed.',
          reference: 'RFC 2918 §3',
          byteRange: { start: 22, end: 23 },
        },
      );

      rootLabel = 'BGP ROUTE-REFRESH Message';
      rootValue = `${subInfo.name} for ${formatAfiSafi(msg.afi, msg.safi)}`;
      rootExplanation =
        'Requests the peer to re-advertise routes for an AFI/SAFI without tearing down the session (or demarcates BoRR/EoRR).';
      rootReference = msg.subtype === 0 ? 'RFC 2918 §3' : 'RFC 7313 §3.2';
      break;
    }

    case 'unknown': {
      if (!isUint8(msg.typeCode)) {
        return err(`Unknown BGP message typeCode must be 0-255 (got ${msg.typeCode}).`);
      }
      const bodyRes = parseHexBytes(msg.bodyHex);
      if (!bodyRes.ok) return err(`Unknown message bodyHex invalid: ${bodyRes.error}`);
      typeCode = msg.typeCode;
      bodyBytes = bodyRes.value;
      if (bodyBytes.length > 0) {
        bodyNodes.push({
          id: 'unknown.body',
          label: 'Message Body (Raw)',
          value: `0x${toHexString(bodyBytes)} (${bodyBytes.length} bytes)`,
          explanation: 'Opaque body bytes for an unrecognized BGP message type.',
          reference: 'RFC 4271 §4.1',
          byteRange: { start: 19, end: 19 + bodyBytes.length },
        });
      }
      rootLabel = `BGP Unknown Message (Type ${msg.typeCode})`;
      rootValue = `${BGP_HEADER_LENGTH + bodyBytes.length} bytes`;
      rootExplanation = 'BGP message with an unrecognized message type code.';
      rootReference = 'RFC 4271 §4.1 / §6.1';
      break;
    }
  }

  const actualLength = BGP_HEADER_LENGTH + bodyBytes.length;
  const wireLength = msg.lengthOverride ?? actualLength;
  if (!isUint16(wireLength)) {
    return err(`BGP Message Length must be 0-65535 (got ${wireLength}).`);
  }
  if (actualLength > BGP_MAX_MESSAGE_LENGTH) {
    warnings.push(
      `BGP message is ${actualLength} bytes, exceeding the classic 4096-byte RFC 4271 §4 limit.`,
    );
  }

  const headerBytes = new Uint8Array(BGP_HEADER_LENGTH);
  headerBytes.set(markerBytes, 0);
  writeUint16BE(headerBytes, 16, wireLength);
  headerBytes[18] = typeCode;

  const bytes = concatBytes(headerBytes, bodyBytes);
  const headerNode = buildCommonHeaderNode(
    markerBytes,
    wireLength,
    actualLength,
    typeCode,
    msg.lengthOverride !== undefined && msg.lengthOverride !== actualLength,
  );

  const tree: DissectionNode = {
    id: 'bgp',
    label: rootLabel,
    value: rootValue,
    explanation: rootExplanation,
    reference: rootReference,
    byteRange: { start: 0, end: bytes.length },
    children: [headerNode, ...bodyNodes],
  };

  return ok({ bytes, tree, warnings });
}

export function encodeBgpMessages(
  messages: readonly BgpMessage[],
  ctx: BgpCodecContext = DEFAULT_BGP_CODEC_CONTEXT,
): Result<Uint8Array> {
  const parts: Uint8Array[] = [];
  for (let i = 0; i < messages.length; i++) {
    const res = encodeBgpMessage(messages[i], ctx);
    if (!res.ok) return err(`Message #${i + 1}: ${res.error}`);
    parts.push(res.value.bytes);
  }
  return ok(concatBytes(...parts));
}
