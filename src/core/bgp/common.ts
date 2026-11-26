import { toHexString } from '../bytes';
import { getMessageTypeName } from './tables';
import {
  BGP_HEADER_LENGTH,
  BGP_MARKER_LENGTH,
  BGP_MESSAGE_TYPE,
  type DissectionNode,
} from './types';

export function isUint8(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xff;
}

export function isUint16(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xffff;
}

export function isUint32(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

export function buildCommonHeaderNode(
  markerBytes: Uint8Array,
  wireLength: number,
  actualLength: number,
  typeCode: number,
  lengthOverridden: boolean,
): DissectionNode {
  const allOnes = markerBytes.every((b) => b === 0xff);
  const typeName = getMessageTypeName(typeCode);

  return {
    id: 'header',
    label: 'BGP Common Header',
    value: `${typeName}, Length ${wireLength} bytes`,
    explanation:
      'Every BGP message begins with a fixed 19-byte header: a 16-byte all-ones Marker, a 2-byte Length, and a 1-byte Type.',
    reference: 'RFC 4271 §4.1',
    byteRange: { start: 0, end: BGP_HEADER_LENGTH },
    children: [
      {
        id: 'header.marker',
        label: 'Marker',
        value: allOnes
          ? 'ff:ff:...:ff (16 bytes of 0xff)'
          : `0x${toHexString(markerBytes)} (non-standard)`,
        explanation:
          '16-octet synchronization marker set to all ones (0xff) for BGP-4 compatibility.',
        reference: 'RFC 4271 §4.1',
        byteRange: { start: 0, end: BGP_MARKER_LENGTH },
      },
      {
        id: 'header.length',
        label: 'Length',
        value: lengthOverridden
          ? `${wireLength} bytes (manual override; actual ${actualLength} bytes)`
          : `${wireLength} bytes`,
        explanation:
          'Total length of the BGP message in octets, including this 19-byte header (valid range 19–4096 bytes per RFC 4271).',
        reference: 'RFC 4271 §4.1',
        byteRange: { start: 16, end: 18 },
      },
      {
        id: 'header.type',
        label: 'Type',
        value: `${typeCode} (${typeName})`,
        explanation:
          'Identifies the BGP message kind: 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE, 5=ROUTE-REFRESH.',
        reference: typeCode === BGP_MESSAGE_TYPE.ROUTE_REFRESH ? 'RFC 2918 §3' : 'RFC 4271 §4.1',
        byteRange: { start: 18, end: 19 },
      },
    ],
  };
}
