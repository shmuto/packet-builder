import type { FieldDoc } from '../definition';

export const TCP_FIELD_DOCS: Readonly<Record<string, FieldDoc>> = {
  srcPort: {
    summary:
      '16-bit port number of the sending endpoint, commonly an ephemeral port (49152-65535) for client connections.',
    reference: 'RFC 9293 §3.1',
  },
  dstPort: {
    summary:
      '16-bit port number of the destination service, such as 80 (HTTP), 179 (BGP), or 443 (HTTPS).',
    reference: 'RFC 9293 §3.1',
  },
  seqNumber: {
    summary:
      '32-bit sequence number of the first payload byte in this segment, or the Initial Sequence Number (ISN) when SYN is set.',
    reference: 'RFC 9293 §3.1',
  },
  ackNumber: {
    summary:
      '32-bit next sequence number the sender expects to receive; meaningful only when the ACK control bit is set.',
    reference: 'RFC 9293 §3.1',
  },
  dataOffset: {
    summary:
      '4-bit TCP header length measured in 32-bit words, marking where payload data begins. Value 5 means a 20-byte header with no options; values 6-15 (24-60 bytes) include TCP options and 32-bit padding.',
    reference: 'RFC 9293 §3.1',
  },
  reserved: {
    summary:
      '4-bit field reserved for future use; senders must set all four bits to 0.',
    reference: 'RFC 9293 §3.1',
  },
  flags: {
    summary:
      '8 control bits managing connection state and congestion signaling: CWR, ECE, URG, ACK, PSH, RST, SYN, and FIN.',
    reference: 'RFC 9293 §3.1',
  },
  windowSize: {
    summary:
      '16-bit receive buffer space (in bytes, before any Window Scale option) that the sender is currently willing to accept.',
    reference: 'RFC 9293 §3.1',
  },
  checksum: {
    summary:
      '16-bit mandatory checksum covering the IPv4/IPv6 pseudo-header, TCP header (including options), and payload to verify end-to-end integrity.',
    reference: 'RFC 9293 §3.1 / RFC 8200 §8.1',
  },
  urgentPointer: {
    summary:
      '16-bit positive offset from the Sequence Number indicating the end of urgent data; valid only when the URG bit is set.',
    reference: 'RFC 9293 §3.1',
  },
  'options.eol.kind': {
    summary:
      '1-byte End of Option List (Kind 0) marking the end of all TCP options. Receivers stop parsing options here and treat remaining header bytes as padding.',
    reference: 'RFC 9293 §3.2',
  },
  'options.nop.kind': {
    summary:
      '1-byte No-Operation (Kind 1) used to align subsequent TCP options on 32-bit word boundaries (for example, before Timestamps or Window Scale).',
    reference: 'RFC 9293 §3.2',
  },
  'options.mss.kind': {
    summary:
      'Option Kind 2 identifying the Maximum Segment Size (MSS) option, exchanged only in SYN segments.',
    reference: 'RFC 9293 §3.2 / §3.7.1',
  },
  'options.mss.length': {
    summary:
      'Fixed 1-byte option length of 4 bytes (Kind + Length + 16-bit MSS value).',
    reference: 'RFC 9293 §3.2 / §3.7.1',
  },
  'options.mss.mss': {
    summary:
      '16-bit Maximum Segment Size in bytes that the sender can receive in a single TCP segment (commonly 1460 bytes for IPv4 over 1500-byte Ethernet).',
    reference: 'RFC 9293 §3.2 / §3.7.1',
  },
  'options.windowScale.kind': {
    summary:
      'Option Kind 3 identifying the TCP Window Scale option, sent only in SYN segments to enable windows larger than 65,535 bytes.',
    reference: 'RFC 7323 §2.2',
  },
  'options.windowScale.length': {
    summary:
      'Fixed 1-byte option length of 3 bytes (Kind + Length + 8-bit shift count).',
    reference: 'RFC 7323 §2.2',
  },
  'options.windowScale.shiftCount': {
    summary:
      '8-bit binary shift count scaling the advertised 16-bit Window Size by 2^shiftCount. Values 0-14 are valid; values above 14 are clamped to 14 by receivers.',
    reference: 'RFC 7323 §2.2 / §2.3',
  },
  'options.sackPermitted.kind': {
    summary:
      'Option Kind 4 indicating that the sender supports Selective Acknowledgments (SACK). Only sent in SYN segments.',
    reference: 'RFC 2018 §2',
  },
  'options.sackPermitted.length': {
    summary:
      'Fixed 1-byte option length of 2 bytes (Kind + Length, with no data bytes).',
    reference: 'RFC 2018 §2',
  },
  'options.sack.kind': {
    summary:
      'Option Kind 5 carrying Selective Acknowledgment (SACK) blocks that report non-contiguous received sequence ranges.',
    reference: 'RFC 2018 §3',
  },
  'options.sack.length': {
    summary:
      '1-byte total length of the SACK option in bytes: 2 + 8 × n for n blocks (at most 4 blocks fit in 40 option bytes, or 3 alongside Timestamps).',
    reference: 'RFC 2018 §3',
  },
  'options.sack.blocks.left': {
    summary:
      '32-bit Left Edge of a SACK block: the first sequence number of a contiguous range of out-of-order bytes that has been received.',
    reference: 'RFC 2018 §3',
  },
  'options.sack.blocks.right': {
    summary:
      '32-bit Right Edge of a SACK block: the sequence number immediately following the last byte of this received contiguous range.',
    reference: 'RFC 2018 §3',
  },
  'options.timestamps.kind': {
    summary:
      'Option Kind 8 identifying the TCP Timestamps option, used for Round-Trip Time Measurement (RTTM) and Protection Against Wrapped Sequences (PAWS).',
    reference: 'RFC 7323 §3.2',
  },
  'options.timestamps.length': {
    summary:
      'Fixed 1-byte option length of 10 bytes (Kind + Length + 32-bit TSval + 32-bit TSecr).',
    reference: 'RFC 7323 §3.2',
  },
  'options.timestamps.tsVal': {
    summary:
      "32-bit Timestamp Value (TSval) containing the current value of the sender's monotonically increasing timestamp clock.",
    reference: 'RFC 7323 §3.2',
  },
  'options.timestamps.tsEcr': {
    summary:
      "32-bit Timestamp Echo Reply (TSecr) echoing a peer's recent TSval when ACK is set, or 0 in an initial SYN segment.",
    reference: 'RFC 7323 §3.2',
  },
  'options.raw.kind': {
    summary:
      '8-bit TCP Option Kind (0-255) for experimental, uncommon, or custom options such as TCP-AO (29), MPTCP (30), or TCP Fast Open (34).',
    reference: 'RFC 9293 §3.1',
  },
  'options.raw.length': {
    summary:
      '8-bit total byte length of this option including the Kind and Length bytes (minimum 2 for TLV-formatted TCP options).',
    reference: 'RFC 9293 §3.1',
  },
  'options.raw.data': {
    summary:
      'Variable-length option-specific payload bytes encoded in hexadecimal following the Kind (and Length) bytes.',
    reference: 'RFC 9293 §3.1',
  },
  optionsPadding: {
    summary:
      'Zero-fill padding bytes (0-3 bytes) appended after TCP options so the TCP header ends on a 32-bit word boundary.',
    reference: 'RFC 9293 §3.1 "Padding"',
  },
};
