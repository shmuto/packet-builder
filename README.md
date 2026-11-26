# tsumiki (packet-builder)

**An interactive, client-side educational packet builder for stacking Ethernet II, VLAN (802.1Q / 802.1ad QinQ), ARP, IPv4, IPv6, ICMP, ICMPv6, GRE, UDP, TCP, and BGP-4 layers like building blocks.**

Everything runs purely in the browser (no backend required) and deploys as a static site on GitHub Pages.

## Features

- **Building-Block Layer Stack**
  - Stack, reorder, add, or remove Ethernet II, VLAN (802.1Q / 802.1ad QinQ), ARP, IPv4, IPv6, ICMP, ICMPv6, GRE (RFC 2784 / RFC 2890), UDP, TCP, and BGP-4 headers in any order (supporting tunneling/encapsulation such as QinQ double-tagging, IP-in-IP, 6in4, 4in6, GRE tunnels, GRETAP Transparent Ethernet Bridging, L2-over-UDP, ICMP-quoted headers, or experimental stacks) alongside UTF-8 text or hexadecimal payloads.
  - Switch between built-in presets (**UDP Packet**, **IPv6 UDP**, **TCP SYN**, **ICMP Ping**, **IPv6 Ping**, **ARP Request**, **VLAN UDP**, **GRE Tunnel**, **BGP OPEN**) to inspect real, valid packets immediately.
- **Auto Calculation + Manual Overrides**
  - EtherType / TPID (`0x0800` for IPv4, `0x86dd` for IPv6, `0x0806` for ARP, `0x8100` for 802.1Q C-tag, `0x88a8` for 802.1ad QinQ S-tag), ARP hardware/protocol metadata, IPv4 Total Length / Protocol (`47` for GRE) / Header Checksum, IPv6 Payload Length / Next Header (`47` for GRE), ICMP Checksum, ICMPv6 Checksum (with IPv6 pseudo-header), GRE Version / Protocol Type (`0x0800` IPv4, `0x86dd` IPv6, `0x6558` GRETAP, `0x0806` ARP, `0x8100` VLAN) / optional Checksum (C=1), UDP Length / Checksum (IPv4 or IPv6 pseudo-header), TCP Data Offset / Checksum (IPv4 or IPv6 pseudo-header), and BGP-4 Marker / Length / Version / Optional Parameters Length are automatically calculated per RFC / IEEE specifications.
  - Toggle any auto-calculated field to **Manual** mode to intentionally craft malformed checksums, lengths, or flags and observe how the raw bytes change.
- **Errors vs. Learning Warnings**
  - Impossible inputs (invalid MAC/IPv4/IPv6 addresses, out-of-range integers such as PCP > 7, VID > 4095, or GRE Version > 7, >65535-byte IPv4/IPv6/UDP/TCP/BGP lengths, >255-byte BGP OPEN Optional Parameters) are reported inline per field without breaking the UI.
  - Protocol edge cases (Ethernet frames under IEEE 802.3's 60-byte minimum, VLAN VID `0` priority-tagged or VID `4095` reserved per IEEE 802.1Q, IPv4 Reserved bit set, ICMPv4 directly above IPv6, ICMPv6 directly above IPv4, GRE Version != 0 per RFC 2784 §2.3.1, UDP checksum `0x0000` disabled over IPv4 per RFC 768 or invalid over IPv6 per RFC 8200 §8.1, BGP Hold Time `1` or `2` seconds, BGP KEEPALIVE with payload, BGP without an underlying TCP layer per RFC 4271, BGP over non-179 TCP ports) surface as non-blocking warnings.
- **Bit-Accurate Inspection & Export**
  - **Bidirectional hover/focus highlighting** links editor fields, hexadecimal dump bytes (+ ASCII), layer segment summaries, and a **unified, color-coded 32-bit header bit diagram** showing all stacked headers continuously in wire order with header-range emphasis—including sub-byte fields such as VLAN PCP (3b) / DEI (1b) / VID (12b), IPv4 Version (4b) / IHL (4b), Flags (3b) / Fragment Offset (13b), IPv6 Version (4b) / Traffic Class (8b) / Flow Label (20b), GRE C / K / S flags & Version (3b), and TCP Data Offset (4b) / Reserved (4b).
  - **One-click export & shareable permalinks**: copy continuous hex strings (**Copy Hex**), formatted hex dumps (**Copy Dump**), download Wireshark-compatible `.pcap` files (**Download .pcap**), or copy a shareable URL (**Copy Link**). Permalinks use a versioned URL fragment (`#p1=<base64url(UTF-8 JSON)>`) that works under GitHub Pages sub-paths and restores the exact layer stack, auto/manual overrides, and payload—including intentionally broken packets.
  - **Import & Decode Hex**: paste raw hex streams or offset-prefixed hex dumps (Ethernet II frames including 802.1Q / 802.1ad / legacy `0x9100` VLAN tags, Raw IPv4 packets, or Raw IPv6 packets, including ICMPv6, 6in4/4in6 tunnels, GRE / GRETAP tunnels with optional Checksum / Key / Sequence Number, and BGP-4 over TCP port 179) to decode them back into editable layers while preserving auto vs. manual checksum/length/TPID states. Because raw bytes only carry standard encapsulations (Ethernet II, Raw IPv4, or Raw IPv6 outermost headers and recognized protocol numbers/ports), custom or non-standard stacks cannot always be reconstructed from exported bytes alone—the inspector flags these mismatches automatically and recommends **Copy Link** to preserve the exact stack.

## Supported Protocols & Specifications

| Layer | Protocol | Reference RFC / Spec | Auto-Calculated Fields (Manual Override Supported) |
| --- | --- | --- | --- |
| L2 | **Ethernet II** (14B) | RFC 894 / IEEE 802.3 | EtherType / TPID (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP, `0x8100` 802.1Q VLAN, `0x88a8` 802.1ad QinQ S-tag) |
| L2 | **VLAN** (4B tag body: TCI + inner EtherType) | IEEE 802.1Q / 802.1ad | Inner EtherType / TPID (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP, `0x8100` inner C-tag) |
| L2.5 | **ARP** (28B) | RFC 826 | Hardware Type (`1`), Protocol Type (`0x0800`), Hardware Size (`6`), Protocol Size (`4`) |
| L3 | **IPv4** (20B, IHL=5 fixed) | RFC 791 / RFC 2003 (IP-in-IP) / RFC 4213 (6in4) | Total Length, Protocol (ICMP=1 / IP-in-IP=4 / TCP=6 / UDP=17 / IPv6=41 / GRE=47), Header Checksum (RFC 1071) |
| L3 | **IPv6** (40B fixed) | RFC 8200 / RFC 2473 (IPv6 tunneling) | Payload Length, Next Header (TCP=6 / UDP=17 / GRE=47 / ICMPv6=58 / IPv4=4 / IPv6=41) |
| L3 (over IPv4) | **ICMP** (8B base) | RFC 792 | Checksum (RFC 1071 over header + payload) |
| L3 (over IPv6) | **ICMPv6** (8B base: Echo / Raw 32-bit) | RFC 4443 | Checksum (RFC 1071 with IPv6 pseudo-header, Next Header 58) |
| L3 (tunnel) | **GRE** (4-16B: optional C / K / S) | RFC 2784 / RFC 2890 | Version (`0`), Protocol Type (`0x0800` IPv4, `0x86dd` IPv6, `0x6558` GRETAP, `0x0806` ARP, `0x8100` VLAN), optional Checksum (RFC 1071 over GRE header + payload) |
| L4 | **UDP** (8B) | RFC 768 / RFC 8200 §8.1 | Length, Checksum (with IPv4/IPv6 pseudo-header; `0x0000` mapped to `0xffff`) |
| L4 | **TCP** (20B base) | RFC 9293 Section 3.1 / RFC 8200 §8.1 | Data Offset (`5`), Checksum (with IPv4/IPv6 pseudo-header; `0x0000` preserved) |
| L7 (over TCP) | **BGP-4** (19-29B: OPEN / UPDATE / NOTIFICATION / KEEPALIVE) | RFC 4271 | Marker (`0xff` × 16), Length, OPEN Version (`4`) & Opt. Parm Len, UPDATE Withdrawn / Path Attr Lengths (`0`) |

## Local Development

Requires Node.js 22+.

```bash
npm install
npm run dev        # Start Vite dev server
npm run test       # Run Vitest unit tests
npm run typecheck  # Run TypeScript type check (tsc --noEmit)
npm run check      # Run typecheck, tests, and production build
```

## Project Structure

- `src/core/` — Pure, DOM-free packet encoding, decoding, validation, and inspection logic (each module paired with `*.test.ts`)
  - `result.ts` — Non-throwing `Result<T>` type and `ok` / `err` helpers
  - `bytes.ts` — MAC / IPv4 / IPv6 (RFC 4291 & RFC 5952) / hex / hex-dump parsing, UTF-8 encode & strict BOM-preserving decode, big-endian readers/writers, hex string & dump formatters
  - `checksum.ts` — RFC 1071 Internet Checksum and IPv4 / IPv6 pseudo-header checksums
  - `layers/` — Types and encoders for Ethernet II, VLAN (802.1Q/802.1ad), ARP, IPv4, IPv6, ICMP, ICMPv6, GRE, UDP, TCP, and BGP-4
  - `packet.ts` — `buildPacket` assembling arbitrary protocol header stacks into raw bytes and contiguous `FieldSpan[]` bit mappings
  - `decode.ts` — Raw byte decoder (`decodePacket`) reconstructing layer stacks & payload from Ethernet II (including 802.1Q / 802.1ad / `0x9100` VLAN tags), Raw IPv4, or Raw IPv6 packets (including ICMPv6, 6in4/4in6 tunnels, GRE / GRETAP tunnels, and BGP-4 over TCP port 179)
  - `permalink.ts` — Versioned shareable permalink encoder/decoder (`#p1=<base64url(UTF-8 JSON)>`) with strict shape validation
  - `roundtrip.ts` — Decode round-trip analyzer (`analyzeDecodeRoundTrip`) detecting when exported bytes will not decode back into the same layer stack
  - `fieldDocs.ts` — Exhaustive per-field beginner summaries and RFC / IEEE specification references
  - `presets.ts` — Default layer factories and UDP / IPv6 UDP / TCP SYN / ICMP Ping / IPv6 Ping / ARP Request / VLAN UDP / GRE Tunnel / BGP OPEN presets
  - `inspector.ts` — Form integer parsing, hex dump rows, layer summaries, bidirectional highlight matching, and 32-bit bit diagram layout
  - `pcap.ts` — Classic libpcap (v2.4) encoder and link-layer type selector for Wireshark export
- `src/ui/` — React presentation components delegating all computation to `src/core/`
  - `layerMeta.ts` — Display metadata and layer factories
  - `FieldControls.tsx` — Text, numeric, auto/manual toggle, and fixed-bit chip controls
  - `LayerCard.tsx` — Collapsible layer editor cards
  - `PayloadCard.tsx` — UTF-8 text / hexadecimal payload editor
  - `ImportHexPanel.tsx` — Raw hex / hex-dump import and decoding panel
  - `BitDiagram.tsx` — RFC-style 32-bit header layout visualizer
  - `HexDumpInspector.tsx` — Export toolbar, layer proportion bar, live hover detail strip, hex/ASCII dump, and warnings/errors

## CI & Deployment

GitHub Actions workflows automate verification, deployment, and review:

| Workflow | Purpose |
| --- | --- |
| `.github/workflows/ci.yml` | Runs `npm run check` on PRs and pushes to `main` |
| `.github/workflows/pages.yml` | Builds and deploys `dist/` to GitHub Pages on pushes to `main` |
| `.github/workflows/claude-review.yml` | Runs automated PR code reviews via Claude Opus |

### Repository Setup

1. In **Settings → Pages**, set Source to **GitHub Actions**.
2. To enable automated PR reviews, install the Claude GitHub App (`https://github.com/apps/claude`) and save a token from `claude setup-token` as the repository secret `CLAUDE_CODE_OAUTH_TOKEN`.
