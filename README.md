# tsumiki (packet-builder)

**An interactive, client-side educational packet builder for stacking Ethernet II, ARP, IPv4, ICMP, UDP, and TCP layers like building blocks.**

Everything runs purely in the browser (no backend required) and deploys as a static site on GitHub Pages.

## Features

- **Building-Block Layer Stack**
  - Stack, reorder, add, or remove Ethernet II, ARP, IPv4, ICMP, UDP, and TCP headers alongside UTF-8 text or hexadecimal payloads.
  - Switch between built-in presets (**UDP Packet**, **TCP SYN**, **ICMP Ping**, **ARP Request**) to inspect real, valid packets immediately.
- **Auto Calculation + Manual Overrides**
  - EtherType (`0x0800` for IPv4, `0x0806` for ARP), ARP hardware/protocol metadata, IPv4 Total Length / Protocol / Header Checksum, ICMP Checksum, UDP Length / Checksum, and TCP Data Offset / Checksum are automatically calculated per RFC specifications.
  - Toggle any auto-calculated field to **Manual** mode to intentionally craft malformed checksums, lengths, or flags and observe how the raw bytes change.
- **Errors vs. Learning Warnings**
  - Impossible inputs (invalid MAC/IPv4 addresses, out-of-range integers, >65535-byte IPv4/UDP/TCP lengths, invalid layer ordering) are reported inline per field without breaking the UI.
  - Protocol edge cases (Ethernet frames under IEEE 802.3's 60-byte minimum, IPv4 Reserved bit set, UDP checksum `0x0000` disabled per RFC 768) surface as non-blocking warnings.
- **Bit-Accurate Inspection & Export**
  - **Bidirectional hover/focus highlighting** links editor fields, hexadecimal dump bytes (+ ASCII), and an **RFC-style 32-bit header bit diagram**—including sub-byte fields such as IPv4 Version (4b) / IHL (4b), Flags (3b) / Fragment Offset (13b), and TCP Data Offset (4b) / Reserved (4b).
  - **One-click export**: copy continuous hex strings (**Copy Hex**), formatted hex dumps (**Copy Dump**), or download Wireshark-compatible `.pcap` files (**Download .pcap**).
  - **Import & Decode Hex**: paste raw hex streams or offset-prefixed hex dumps (Ethernet II frames or Raw IPv4 packets) to decode them back into editable layers while preserving auto vs. manual checksum/length states.

## Supported Protocols & Specifications

| Layer | Protocol | Reference RFC / Spec | Auto-Calculated Fields (Manual Override Supported) |
| --- | --- | --- | --- |
| L2 | **Ethernet II** (14B) | RFC 894 / IEEE 802.3 | EtherType (`0x0800` for IPv4, `0x0806` for ARP) |
| L2.5 | **ARP** (28B) | RFC 826 | Hardware Type (`1`), Protocol Type (`0x0800`), Hardware Size (`6`), Protocol Size (`4`) |
| L3 | **IPv4** (20B, IHL=5 fixed) | RFC 791 | Total Length, Protocol (ICMP=1 / TCP=6 / UDP=17), Header Checksum (RFC 1071) |
| L3 (over IPv4) | **ICMP** (8B base) | RFC 792 | Checksum (RFC 1071 over header + payload) |
| L4 | **UDP** (8B) | RFC 768 | Length, Checksum (with IPv4 pseudo-header; `0x0000` mapped to `0xffff`) |
| L4 | **TCP** (20B base) | RFC 9293 Section 3.1 | Data Offset (`5`), Checksum (with IPv4 pseudo-header; `0x0000` preserved) |

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
  - `bytes.ts` — MAC / IPv4 / hex / hex-dump parsing, UTF-8 encode & strict BOM-preserving decode, big-endian readers/writers, hex string & dump formatters
  - `checksum.ts` — RFC 1071 Internet Checksum and IPv4 pseudo-header checksum
  - `layers/` — Types and encoders for Ethernet II, ARP, IPv4, ICMP, UDP, and TCP
  - `packet.ts` — Layer order validation and `buildPacket` producing raw bytes and contiguous `FieldSpan[]` bit mappings
  - `decode.ts` — Raw byte decoder (`decodePacket`) reconstructing layer stacks & payload from Ethernet II or Raw IPv4 packets
  - `presets.ts` — Default layer factories and UDP / TCP SYN / ICMP Ping / ARP Request presets
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
