import type { FieldDoc } from '../definition';

export const IPV4_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  version: {
    summary:
      '4-bit IP version number identifying the header format. Always 4 for IPv4 packets.',
    reference: 'RFC 791 §3.1',
  },
  ihl: {
    summary:
      'Internet Header Length measured in 32-bit words. Value 5 means a 20-byte header with no options; values 6-15 (24-60 bytes) include IPv4 options and 32-bit padding.',
    reference: 'RFC 791 §3.1',
  },
  tos: {
    summary:
      '8-bit quality-of-service field now split into a 6-bit DSCP priority value and 2-bit ECN congestion indicator. Defaults to 0x00 for best-effort traffic.',
    reference: 'RFC 791 §3.1 / RFC 2474 §3 / RFC 3168 §5',
  },
  totalLength: {
    summary:
      'Total length of the IPv4 packet in bytes, including both the header (with options) and payload. Minimum is 20 bytes and maximum is 65,535 bytes.',
    reference: 'RFC 791 §3.1',
  },
  identification: {
    summary:
      '16-bit value assigned by the sender to help receivers group fragments belonging to the same original IPv4 datagram.',
    reference: 'RFC 791 §3.1',
  },
  flags: {
    summary:
      "3-bit fragmentation control field: Reserved (must be 0), DF (Don't Fragment), and MF (More Fragments follow).",
    reference: 'RFC 791 §3.1',
  },
  fragmentOffset: {
    summary:
      "Position of this fragment's payload relative to the start of the original datagram, measured in 8-byte blocks. Zero for unfragmented packets and initial fragments.",
    reference: 'RFC 791 §3.1',
  },
  ttl: {
    summary:
      'Hop limit decremented by each router; the packet is dropped when it reaches 0 to prevent routing loops. Common initial values are 64 and 128.',
    reference: 'RFC 791 §3.1',
  },
  protocol: {
    summary:
      '8-bit IANA number identifying the next encapsulated protocol in the IPv4 payload. Common values are 1 (ICMP), 2 (IGMP), 4 (IP-in-IP), 6 (TCP), 17 (UDP), 41 (IPv6), and 47 (GRE).',
    reference: 'RFC 791 §3.1',
  },
  headerChecksum: {
    summary:
      "16-bit one's-complement checksum covering the entire IPv4 header including options (not the payload). Routers recompute it whenever TTL or options change.",
    reference: 'RFC 791 §3.1',
  },
  srcIp: {
    summary: '32-bit IPv4 address of the host that originated the packet.',
    reference: 'RFC 791 §3.1',
  },
  dstIp: {
    summary: '32-bit IPv4 address of the final destination host.',
    reference: 'RFC 791 §3.1',
  },
  'options.copied': {
    summary:
      '1-bit Copied flag (MSB of the IPv4 option type byte). When 1, the option is copied into all fragments on IPv4 fragmentation; when 0, it appears only in the first fragment.',
    reference: 'RFC 791 §3.1',
  },
  'options.class': {
    summary:
      '2-bit Option Class (bits 1-2 of the IPv4 option type byte): 0 = Control, 2 = Debugging and Measurement (1 and 3 are reserved).',
    reference: 'RFC 791 §3.1',
  },
  'options.eol.number': {
    summary:
      '5-bit Option Number 0 (Type 0: copied=0, class=0, number=0) identifying End of Option List. Receivers stop scanning options here and treat remaining header bytes as padding.',
    reference: 'RFC 791 §3.1',
  },
  'options.nop.number': {
    summary:
      '5-bit Option Number 1 (Type 1: copied=0, class=0, number=1) identifying No Operation, used between options to align subsequent options on 32-bit boundaries.',
    reference: 'RFC 791 §3.1',
  },
  'options.rr.number': {
    summary:
      '5-bit Option Number 7 (Type 7: copied=0, class=0, number=7) identifying Record Route, where each router records its outgoing IPv4 interface address.',
    reference: 'RFC 791 §3.1',
  },
  'options.rr.length': {
    summary:
      '8-bit total byte length of the Record Route option (3 + 4 × n for n IPv4 address slots, up to 39 bytes / 9 hops).',
    reference: 'RFC 791 §3.1',
  },
  'options.rr.pointer': {
    summary:
      '8-bit 1-based byte offset into the Record Route option pointing to the next free address slot. Starts at 4 and advances by 4 per recorded hop.',
    reference: 'RFC 791 §3.1',
  },
  'options.rr.addrs': {
    summary:
      "32-bit IPv4 address slot in the Record Route option storing a router's interface address (0.0.0.0 when still unused).",
    reference: 'RFC 791 §3.1',
  },
  'options.timestamp.number': {
    summary:
      '5-bit Option Number 4 in Class 2 (Type 68: copied=0, class=2, number=4) identifying Internet Timestamp for recording router timestamps along the path.',
    reference: 'RFC 791 §3.1',
  },
  'options.timestamp.length': {
    summary:
      '8-bit total byte length of the Internet Timestamp option (4 + data bytes, minimum 4 and maximum 40).',
    reference: 'RFC 791 §3.1',
  },
  'options.timestamp.pointer': {
    summary:
      '8-bit 1-based byte offset pointing to the next free timestamp slot in the option. Minimum valid initial value is 5.',
    reference: 'RFC 791 §3.1',
  },
  'options.timestamp.overflow': {
    summary:
      '4-bit counter incremented by routers that could not record a timestamp because the option space was already full.',
    reference: 'RFC 791 §3.1',
  },
  'options.timestamp.flag': {
    summary:
      "4-bit format selector: 0 = 32-bit timestamps only, 1 = each timestamp preceded by the router's IPv4 address, 3 = prespecified IPv4 addresses.",
    reference: 'RFC 791 §3.1',
  },
  'options.timestamp.data': {
    summary:
      'Variable-length timestamp data area (encoded in hexadecimal) containing 32-bit millisecond timestamps and optional IPv4 addresses according to Flag.',
    reference: 'RFC 791 §3.1',
  },
  'options.lsrr.number': {
    summary:
      '5-bit Option Number 3 with Copied=1 (Type 131: copied=1, class=0, number=3) identifying Loose Source and Record Route. Modern routers commonly drop source-routed packets.',
    reference: 'RFC 791 §3.1 / RFC 7126 §4.3',
  },
  'options.lsrr.length': {
    summary:
      '8-bit total byte length of the Loose Source and Record Route option (3 + 4 × n for n IPv4 addresses).',
    reference: 'RFC 791 §3.1',
  },
  'options.lsrr.pointer': {
    summary:
      '8-bit 1-based byte offset pointing to the next loose-source-routed IPv4 hop (starts at 4 and increments by 4 at each listed hop).',
    reference: 'RFC 791 §3.1',
  },
  'options.lsrr.addrs': {
    summary:
      '32-bit IPv4 hop address listed in the Loose Source and Record Route option.',
    reference: 'RFC 791 §3.1',
  },
  'options.ssrr.number': {
    summary:
      '5-bit Option Number 9 with Copied=1 (Type 137: copied=1, class=0, number=9) identifying Strict Source and Record Route. Modern routers commonly drop source-routed packets.',
    reference: 'RFC 791 §3.1 / RFC 7126 §4.4',
  },
  'options.ssrr.length': {
    summary:
      '8-bit total byte length of the Strict Source and Record Route option (3 + 4 × n for n IPv4 addresses).',
    reference: 'RFC 791 §3.1',
  },
  'options.ssrr.pointer': {
    summary:
      '8-bit 1-based byte offset pointing to the next strict-source-routed IPv4 hop (starts at 4 and increments by 4 at each hop).',
    reference: 'RFC 791 §3.1',
  },
  'options.ssrr.addrs': {
    summary:
      '32-bit IPv4 hop address listed in the Strict Source and Record Route option.',
    reference: 'RFC 791 §3.1',
  },
  'options.routerAlert.number': {
    summary:
      '5-bit Option Number 20 with Copied=1 (Type 148 / 0x94: copied=1, class=0, number=20) identifying Router Alert, still widely used by IGMP and RSVP so transit routers inspect control packets.',
    reference: 'RFC 2113 §2.1',
  },
  'options.routerAlert.length': {
    summary:
      'Fixed 8-bit option length of 4 bytes (Type + Length + 16-bit Value).',
    reference: 'RFC 2113 §2.1',
  },
  'options.routerAlert.value': {
    summary:
      '16-bit Router Alert value. Value 0 means "Router shall examine packet" (used by IGMP and RSVP); values 1-65535 are reserved.',
    reference: 'RFC 2113 §2.1',
  },
  'options.raw.number': {
    summary:
      '5-bit Option Number combined with Copied (1b) and Class (2b) into the 8-bit IPv4 option type byte for custom or uncommon options such as CIPSO (Type 134).',
    reference: 'RFC 791 §3.1',
  },
  'options.raw.length': {
    summary:
      '8-bit total byte length of this IPv4 option including the Type and Length bytes (minimum 2 for variable-length options).',
    reference: 'RFC 791 §3.1',
  },
  'options.raw.data': {
    summary:
      'Variable-length IPv4 option payload bytes encoded in hexadecimal following the Type (and Length) bytes.',
    reference: 'RFC 791 §3.1',
  },
  optionsPadding: {
    summary:
      'Zero-fill padding bytes (0-3 bytes) appended after IPv4 options so the IPv4 header ends on a 32-bit word boundary.',
    reference: 'RFC 791 §3.1 "Padding"',
  },
};
