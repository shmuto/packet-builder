# tsumiki（packet-builder）

**Ethernet II / IPv4 / ICMP / UDP / TCP の各レイヤーを積み木のように重ねて、ネットワークパケットのバイト列を組み立てて学べる Web アプリです。**

ブラウザだけで完結し（サーバー処理なし）、GitHub Pages 上でそのまま動作します。

## 特徴

- **積み木のようにレイヤーを構成**
  - L2（Ethernet II）→ L3（IPv4）→ L4（ICMP / UDP / TCP）→ Payload（UTF-8 テキスト / 16 進バイト列）を自由に組み合わせてパケットを生成できます。
  - 単体レイヤー（例：IPv4 のみ、UDP のみ）や定番プリセット（UDP パケット / TCP SYN / ICMP Echo Request）からすぐに試せます。
- **「自動計算」と「学習用の手動上書き」**
  - EtherType・全長・プロトコル番号・RFC 1071 チェックサム・IPv4 擬似ヘッダチェックサムなどは自動で計算します。
  - すべての自動計算フィールドは手動上書きにも対応しているため、「正しいパケット」と「意図的に壊したチェックサムや長さ」を並べて比較できます。
- **エラーと学習ヒント（警告）の分離**
  - エンコード不能な入力（不正な MAC/IP、範囲外の整数、65535 バイト超過、不正なレイヤー順）はエラーとして該当フィールドごとに報告します。
  - IEEE 802.3 の最小フレーム長 60 バイト未満、IPv4 予約ビット ON、UDP チェックサム未使用（`0x0000`）など、仕様上知っておくべき状態は生成を止めずに警告として知らせます。
- **ビット単位のフィールド対応表（`FieldSpan`）**
  - IPv4 の Version（4bit）/ IHL（4bit）、Flags（3bit）/ Fragment Offset（13bit）、TCP の Data Offset（4bit）/ Reserved（4bit）/ Control Bits（8bit）といったサブバイト構造を含め、全フィールドのビット位置を正確に追跡します。

## 対応プロトコルと参照仕様

| 層 | プロトコル | 参照 RFC / 規格 | 自動計算されるフィールド（手動上書き可） |
| --- | --- | --- | --- |
| L2 | **Ethernet II**（14B） | RFC 894 / IEEE 802.3 | EtherType（直上が IPv4 のとき `0x0800`） |
| L3 | **IPv4**（オプションなし 20B, IHL=5） | RFC 791 | Total Length、Protocol（ICMP=1 / TCP=6 / UDP=17）、Header Checksum（RFC 1071） |
| L3.5 | **ICMP**（基本 8B） | RFC 792 | Checksum（ヘッダ＋ペイロード全体の RFC 1071） |
| L4 | **UDP**（8B） | RFC 768 | Length、Checksum（IPv4 擬似ヘッダ含む。計算結果 `0x0000` は `0xffff` に変換） |
| L4 | **TCP**（オプションなし基本 20B） | RFC 9293 Section 3.1 | Data Offset（`5`）、Checksum（IPv4 擬似ヘッダ含む。`0x0000` はそのまま格納） |

## 実装状況（ロードマップ）

- [x] **Step 1**: バイト列ユーティリティ・RFC 1071 チェックサム・IPv4 擬似ヘッダチェックサム
- [x] **Step 2**: プロトコルエンコーダ（Ethernet II / IPv4 / ICMP / UDP / TCP）・ビット範囲マップ・定番プリセット
- [ ] **Step 3**: 積み木レイヤーエディタ UI & ライブ 16 進ダンプ（プリセット切替・自動/手動トグル・エラー/警告表示）
- [ ] **Step 4**: フィールド⇔バイト双方向ハイライト・RFC 風 32-bit ビット図・Hex コピー＆Wireshark 向け `.pcap` ダウンロード

## 使い方・ローカル開発

Node.js 22 以上を前提としています。

```bash
npm install
npm run dev        # ローカル開発サーバーを起動
npm run test       # Vitest ユニットテストを実行
npm run typecheck  # TypeScript 型チェック（tsc --noEmit）
npm run check      # 型チェック・テスト・本番ビルドを一括実行
```

## ディレクトリ構成

- `src/core/`：パケット組み立てロジック（React / DOM 非依存。各モジュールと同階層に `*.test.ts` を配置）
  - `result.ts`：例外を投げずに成功・エラーを返す `Result<T>`
  - `bytes.ts`：MAC / IPv4 / 16 進文字列パース、UTF-8 変換、ビッグエンディアン書き込み、16 進ダンプ整形
  - `checksum.ts`：RFC 1071 インターネットチェックサムおよび IPv4 擬似ヘッダチェックサム
  - `layers/`：Ethernet II / IPv4 / ICMP / UDP / TCP の型定義・エンコーダ
  - `packet.ts`：レイヤー順序検証とパケット全体＋`FieldSpan[]` を組み立てる `buildPacket`
  - `presets.ts`：UDP パケット / TCP SYN / ICMP Ping の初期プリセット
- `src/ui/`：React コンポーネント（計算は `src/core/` に委譲し表示のみを担当。Step 3 で追加予定）

## CI・公開

GitHub Actions により以下を自動実行しています。

- `.github/workflows/ci.yml`：PR および `main` push 時に `npm run check` を実行
- `.github/workflows/pages.yml`：`main` へのマージ時に GitHub Pages へ自動公開
- `.github/workflows/claude-review.yml`：PR 作成・更新時に自動コードレビューを実行
