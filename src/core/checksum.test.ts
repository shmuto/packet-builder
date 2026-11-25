import { describe, expect, it } from 'vitest';
import { internetChecksum, ipv4PseudoHeaderChecksum } from './checksum';

describe('internetChecksum', () => {
  it('RFC 1071 Section 3 の例と一致する', () => {
    const data = new Uint8Array([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]);
    expect(internetChecksum(data)).toBe(0x220d);
  });

  it('既知の IPv4 ヘッダ例のチェックサムと一致する', () => {
    const header = new Uint8Array([
      0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
      0x00, 0x00,
      0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ]);
    expect(internetChecksum(header)).toBe(0xb861);
  });

  it('奇数長のデータは末尾に 0x00 を補って計算する', () => {
    const odd = new Uint8Array([0x00, 0x01, 0xf2]);
    const padded = new Uint8Array([0x00, 0x01, 0xf2, 0x00]);
    expect(internetChecksum(odd)).toBe(internetChecksum(padded));
    expect(internetChecksum(odd)).toBe(0x0dfe);

    const single = new Uint8Array([0xab]);
    expect(internetChecksum(single)).toBe(internetChecksum(new Uint8Array([0xab, 0x00])));
    expect(internetChecksum(single)).toBe(0x54ff);
  });

  it('正しいチェックサムを埋めたデータを再計算すると 0 になる', () => {
    const rfcWithChecksum = new Uint8Array([
      0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x22, 0x0d,
    ]);
    expect(internetChecksum(rfcWithChecksum)).toBe(0x0000);

    const ipv4WithChecksum = new Uint8Array([
      0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
      0xb8, 0x61,
      0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ]);
    expect(internetChecksum(ipv4WithChecksum)).toBe(0x0000);
  });

  it('空データやキャリー折り畳みの境界値を正しく計算する', () => {
    expect(internetChecksum(new Uint8Array(0))).toBe(0xffff);
    expect(internetChecksum(new Uint8Array([0x00, 0x00]))).toBe(0xffff);
    expect(internetChecksum(new Uint8Array([0xff, 0xff]))).toBe(0x0000);
    expect(internetChecksum(new Uint8Array([0x80, 0x00, 0x80, 0x00]))).toBe(0xfffe);
    expect(internetChecksum(new Uint8Array([0xff, 0xff, 0xff, 0xff]))).toBe(0x0000);
  });
});

describe('ipv4PseudoHeaderChecksum', () => {
  it('奇数長 UDP セグメントの擬似ヘッダチェックサムを計算し、埋め戻すと 0 になる', () => {
    const srcIp = new Uint8Array([192, 168, 0, 1]);
    const dstIp = new Uint8Array([192, 168, 0, 2]);
    // UDP: srcPort=12345(0x3039), dstPort=80(0x0050), length=13(0x000d), checksum=0, payload="Hello"
    const segment = new Uint8Array([
      0x30, 0x39, 0x00, 0x50, 0x00, 0x0d, 0x00, 0x00,
      0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ]);

    const result = ipv4PseudoHeaderChecksum({ srcIp, dstIp, protocol: 17, segment });
    expect(result).toEqual({ ok: true, value: 0x2a25 });

    // チェックサムを埋め戻して再計算すると 0 になる
    const withChecksum = new Uint8Array(segment);
    withChecksum[6] = 0x2a;
    withChecksum[7] = 0x25;
    expect(
      ipv4PseudoHeaderChecksum({ srcIp, dstIp, protocol: 17, segment: withChecksum }),
    ).toEqual({ ok: true, value: 0x0000 });
  });

  it('計算結果が 0x0000 になる場合は生の 0x0000 を返す（UDP 変換は呼び出し側の責務）', () => {
    const srcIp = new Uint8Array([0, 0, 0, 0]);
    const dstIp = new Uint8Array([0, 0, 0, 0]);
    const segment = new Uint8Array([0xff, 0xde, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00]);
    expect(ipv4PseudoHeaderChecksum({ srcIp, dstIp, protocol: 17, segment })).toEqual({
      ok: true,
      value: 0x0000,
    });
  });

  it('不正な IP 長・プロトコル番号・65535 バイト超のセグメントはエラーを返す', () => {
    const validIp = new Uint8Array([10, 0, 0, 1]);
    const validSeg = new Uint8Array(8);

    expect(
      ipv4PseudoHeaderChecksum({
        srcIp: new Uint8Array([10, 0, 0]),
        dstIp: validIp,
        protocol: 17,
        segment: validSeg,
      }).ok,
    ).toBe(false);

    expect(
      ipv4PseudoHeaderChecksum({
        srcIp: validIp,
        dstIp: new Uint8Array([10, 0, 0, 1, 2]),
        protocol: 17,
        segment: validSeg,
      }).ok,
    ).toBe(false);

    expect(
      ipv4PseudoHeaderChecksum({ srcIp: validIp, dstIp: validIp, protocol: -1, segment: validSeg })
        .ok,
    ).toBe(false);
    expect(
      ipv4PseudoHeaderChecksum({ srcIp: validIp, dstIp: validIp, protocol: 256, segment: validSeg })
        .ok,
    ).toBe(false);
    expect(
      ipv4PseudoHeaderChecksum({
        srcIp: validIp,
        dstIp: validIp,
        protocol: 6.5,
        segment: validSeg,
      }).ok,
    ).toBe(false);

    // 上限ちょうど 65535 バイトは OK、65536 バイトはエラー
    expect(
      ipv4PseudoHeaderChecksum({
        srcIp: validIp,
        dstIp: validIp,
        protocol: 17,
        segment: new Uint8Array(65535),
      }).ok,
    ).toBe(true);
    expect(
      ipv4PseudoHeaderChecksum({
        srcIp: validIp,
        dstIp: validIp,
        protocol: 17,
        segment: new Uint8Array(65536),
      }).ok,
    ).toBe(false);
  });
});
