# tsumiki (packet-builder)

**See what every bit of a packet header means — and what happens when you change it — right in your browser.**

**Try it live:** https://shmuto.github.io/packet-builder/

![tsumiki interactive packet builder screenshot](docs/screenshot.png)

Everything runs purely in the browser (no backend required) and deploys as a static site on GitHub Pages.

## Features

- **Building-block layer stack**: Stack, reorder, add, or remove protocol headers in any order—including tunneling, double-tagging, and experimental stacks—or start from built-in presets.
- **Auto calculation with manual overrides**: Checksums, lengths, EtherTypes, IP protocols, IHL, Data Offset, and flags are calculated automatically per RFC / IEEE specifications, and any field can be toggled to **Manual** mode to intentionally break a packet and observe the raw bytes change.
- **Errors vs. learning warnings**: Invalid inputs are reported inline per field without breaking the UI, while protocol edge cases and RFC violations surface as non-blocking learning warnings.
- **Bit-accurate bidirectional inspection**: Hovering or focusing a field, hex byte, layer segment, or 32-bit header bit-diagram cell highlights the exact matching bits across the packet with inline RFC / IEEE section references.
- **Import & decode raw hex**: Paste raw hex streams or offset-prefixed hex dumps to decode them back into editable layer stacks while preserving auto vs. manual states.
- **One-click export & shareable permalinks**: Copy continuous hex strings or formatted hex dumps, download Wireshark-compatible `.pcap` files, or share exact packet states (including broken overrides) via `#p1=...` URL fragments.

## Supported Protocols & Specifications

| Layer | Protocol | Reference RFC / Spec | Auto-Calculated Fields (Manual Override Supported) |
| --- | --- | --- | --- |
| L2 | **Ethernet II** (14B) | RFC 894 / IEEE 802.3 | EtherType / TPID (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP, `0x8100` 802.1Q VLAN, `0x88a8` 802.1ad QinQ S-tag) |
| L2 | **VLAN** (4B tag body: TCI + inner EtherType) | IEEE 802.1Q / 802.1ad | Inner EtherType / TPID (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP, `0x8100` inner C-tag) |
| L2.5 | **ARP** (28B) | RFC 826 | Hardware Type (`1`), Protocol Type (`0x0800`), Hardware Size (`6`), Protocol Size (`4`) |
| L3 | **IPv4** (20–60B, IHL 5–15 + options) | RFC 791 / RFC 2113 / RFC 2003 / RFC 4213 | IHL, Total Length, Protocol (ICMP=1 / IP-in-IP=4 / TCP=6 / UDP=17 / IPv6=41 / GRE=47), Header Checksum (RFC 1071) |
| L3 | **IPv6** (40B fixed) | RFC 8200 / RFC 2473 (IPv6 tunneling) | Payload Length, Next Header (TCP=6 / UDP=17 / GRE=47 / ICMPv6=58 / IPv4=4 / IPv6=41) |
| L3 (over IPv4) | **ICMP** (8B base) | RFC 792 | Checksum (RFC 1071 over header + payload) |
| L3 (over IPv6) | **ICMPv6** (8B base: Echo / Raw 32-bit) | RFC 4443 | Checksum (RFC 1071 with IPv6 pseudo-header, Next Header 58) |
| L3 (tunnel) | **GRE** (4-16B: optional C / K / S) | RFC 2784 / RFC 2890 | Version (`0`), Protocol Type (`0x0800` IPv4, `0x86dd` IPv6, `0x6558` GRETAP, `0x0806` ARP, `0x8100` VLAN), optional Checksum (RFC 1071 over GRE header + payload) |
| L4 | **UDP** (8B) | RFC 768 / RFC 8200 §8.1 | Length, Checksum (with IPv4/IPv6 pseudo-header; `0x0000` mapped to `0xffff`) |
| L4 | **TCP** (20–60B, Data Offset 5–15 + options) | RFC 9293 / RFC 7323 / RFC 2018 / RFC 8200 §8.1 | Data Offset (`5`–`15`), Checksum (with IPv4/IPv6 pseudo-header; `0x0000` preserved) |
| L4.5 (over UDP 4789) | **VXLAN** (8B) | RFC 7348 §5 | Flags (`0x08` I-flag valid VNI) |
| L7 (over TCP) | **BGP-4** (19-29B: OPEN / UPDATE / NOTIFICATION / KEEPALIVE) | RFC 4271 | Marker (`0xff` × 16), Length, OPEN Version (`4`) & Opt. Parm Len, UPDATE Withdrawn / Path Attr Lengths (`0`) |

## Local Development

Requires Node.js 22+.

```bash
npm install
npm run dev                     # Start Vite dev server
npm run test                    # Run Vitest unit tests
npm run typecheck               # Run TypeScript type check (tsc --noEmit)
npm run check                   # Run typecheck, tests, and production build
npm run e2e                     # Run Playwright E2E tests (default headless shell)
PW_CHANNEL=chromium npm run e2e # Run Playwright E2E tests in full Chromium (new headless mode)
```

## Project Structure

- `src/core/` — Pure, DOM-free packet encoding, decoding, validation, and inspection logic (each module paired with `*.test.ts`)
  - `result.ts` — Non-throwing `Result<T>` type and `ok` / `err` helpers
  - `bytes.ts` — MAC / IPv4 / IPv6 (RFC 4291 & RFC 5952) / hex / hex-dump parsing, UTF-8 encode & strict BOM-preserving decode, big-endian readers/writers, hex string & dump formatters
  - `checksum.ts` — RFC 1071 Internet Checksum and IPv4 / IPv6 pseudo-header checksums
  - `layers/` — Types and encoders for Ethernet II, VLAN (802.1Q/802.1ad), ARP, IPv4, IPv6, ICMP, ICMPv6, GRE, UDP, TCP, VXLAN, and BGP-4
  - `packet.ts` — `buildPacket` assembling arbitrary protocol header stacks into raw bytes and contiguous `FieldSpan[]` bit mappings
  - `decode.ts` — Raw byte decoder (`decodePacket`) reconstructing layer stacks & payload from Ethernet II (including 802.1Q / 802.1ad / `0x9100` VLAN tags), Raw IPv4, or Raw IPv6 packets (including ICMPv6, 6in4/4in6 tunnels, GRE / GRETAP tunnels, VXLAN overlays over UDP port 4789, and BGP-4 over TCP port 179)
  - `permalink.ts` — Versioned shareable permalink encoder/decoder (`#p1=<base64url(UTF-8 JSON)>`) with strict shape validation
  - `roundtrip.ts` — Decode round-trip analyzer (`analyzeDecodeRoundTrip`) detecting when exported bytes will not decode back into the same layer stack
  - `fieldDocs.ts` — Exhaustive per-field beginner summaries and RFC / IEEE specification references
  - `presets.ts` — Default layer factories and UDP / IPv6 UDP / TCP SYN / ICMP Ping / IPv6 Ping / ARP Request / VLAN UDP / GRE Tunnel / VXLAN Overlay / BGP OPEN presets
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
