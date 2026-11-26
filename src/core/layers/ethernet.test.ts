import { describe, expect, it } from 'vitest';
import { encodeEthernet } from './ethernet';
import { autoValue, manualValue } from './types';

describe('encodeEthernet', () => {
  it('標準的な Ethernet II ヘッダ（14 バイト）を組み立てられる', () => {
    const result = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: '00:11:22:33:44:55',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'ipv4', upperBytesLength: 46 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes).toEqual(
      new Uint8Array([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
      ]),
    );
    expect(result.warnings).toHaveLength(0);
    expect(result.resolvedAutoValues).toEqual({ etherType: 0x0800 });
  });

  it('手動 EtherType を優先し、IPv4 以外の値には警告を出す', () => {
    const result = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: 'ff:ff:ff:ff:ff:ff',
        srcMac: '00:00:00:00:00:00',
        etherType: manualValue(0x86dd),
      },
      { layerIndex: 0, upperLayerType: 'ipv4', upperBytesLength: 46 },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.bytes.slice(12, 14)).toEqual(new Uint8Array([0x86, 0xdd]));
    expect(result.warnings.some((w) => w.fieldId === 'etherType')).toBe(true);
  });

  it('直上が ARP のとき EtherType を自動で 0x0806 に設定する（RFC 826）', () => {
    const autoArp = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: 'ff:ff:ff:ff:ff:ff',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'arp', upperBytesLength: 46 },
    );

    expect(autoArp.ok).toBe(true);
    if (!autoArp.ok) return;
    expect(autoArp.bytes.slice(12, 14)).toEqual(new Uint8Array([0x08, 0x06]));
    expect(autoArp.resolvedAutoValues).toEqual({ etherType: 0x0806 });
    expect(autoArp.warnings).toHaveLength(0);

    const manualWrong = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: 'ff:ff:ff:ff:ff:ff',
        srcMac: '66:77:88:99:aa:bb',
        etherType: manualValue(0x0800),
      },
      { layerIndex: 0, upperLayerType: 'arp', upperBytesLength: 46 },
    );
    expect(manualWrong.ok).toBe(true);
    if (!manualWrong.ok) return;
    expect(manualWrong.warnings.some((w) => w.fieldId === 'etherType' && w.message.includes('0x0806'))).toBe(true);
  });

  it('直上が IPv6 のとき EtherType を自動で 0x86dd に設定する（RFC 8200）', () => {
    const autoIPv6 = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: '00:11:22:33:44:55',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'ipv6', upperBytesLength: 53 },
    );

    expect(autoIPv6.ok).toBe(true);
    if (!autoIPv6.ok) return;
    expect(autoIPv6.bytes.slice(12, 14)).toEqual(new Uint8Array([0x86, 0xdd]));
    expect(autoIPv6.resolvedAutoValues).toEqual({ etherType: 0x86dd });
    expect(autoIPv6.warnings).toHaveLength(0);
  });

  it('selects 0x8100 for single VLAN tag and 0x88a8 (802.1ad S-tag) for double-tagged QinQ', () => {
    const singleTag = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: '00:11:22:33:44:55',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'vlan', upperNextLayerType: 'ipv4', upperBytesLength: 46 },
    );
    expect(singleTag.ok).toBe(true);
    if (singleTag.ok) {
      expect(singleTag.bytes.slice(12, 14)).toEqual(new Uint8Array([0x81, 0x00]));
      expect(singleTag.resolvedAutoValues).toEqual({ etherType: 0x8100 });
      expect(singleTag.warnings).toHaveLength(0);
    }

    const qinq = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: '00:11:22:33:44:55',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'vlan', upperNextLayerType: 'vlan', upperBytesLength: 46 },
    );
    expect(qinq.ok).toBe(true);
    if (qinq.ok) {
      expect(qinq.bytes.slice(12, 14)).toEqual(new Uint8Array([0x88, 0xa8]));
      expect(qinq.resolvedAutoValues).toEqual({ etherType: 0x88a8 });
      expect(qinq.warnings).toHaveLength(0);
    }
  });

  it('フレーム長 59 バイトでは警告が出て、ちょうど 60 バイトでは警告が出ない（IEEE 802.3）', () => {
    const shortFrame = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: '00:11:22:33:44:55',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'ipv4', upperBytesLength: 45 }, // 14 + 45 = 59
    );

    expect(shortFrame.ok).toBe(true);
    if (!shortFrame.ok) return;
    expect(shortFrame.warnings.some((w) => w.message.includes('60 bytes'))).toBe(true);

    const exactMinFrame = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: '00:11:22:33:44:55',
        srcMac: '66:77:88:99:aa:bb',
        etherType: autoValue(),
      },
      { layerIndex: 0, upperLayerType: 'ipv4', upperBytesLength: 46 }, // 14 + 46 = 60
    );

    expect(exactMinFrame.ok).toBe(true);
    if (!exactMinFrame.ok) return;
    expect(exactMinFrame.warnings).toHaveLength(0);
  });

  it('不正な MAC アドレスや範囲外の EtherType はエラーを返す', () => {
    const result = encodeEthernet(
      {
        type: 'ethernet',
        dstMac: 'invalid',
        srcMac: 'zz:77:88:99:aa:bb',
        etherType: manualValue(0x10000),
      },
      { layerIndex: 0, upperLayerType: 'ipv4', upperBytesLength: 46 },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.map((e) => e.fieldId)).toEqual(['dstMac', 'srcMac', 'etherType']);
  });
});
