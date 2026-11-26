import { readFileSync } from 'node:fs';
import { expect, test } from './fixtures';

test.describe('BGP session ladder, config interactions, hex decoder, and pcap export', () => {
  test('renders ebgp-ipv4-basic arrows in order and toggles TCP steps', async ({ page }) => {
    await page.goto('/');

    const bgpOptions = page.locator('[data-step-kind="bgp"]');
    await expect(bgpOptions).toHaveCount(9);

    const labels = await bgpOptions.locator('.bgp-step-label').allTextContents();
    expect(labels).toEqual([
      'OPEN (AS 65001, Hold 90s, 3 caps)',
      'OPEN (AS 65002, Hold 90s, 3 caps)',
      'KEEPALIVE',
      'KEEPALIVE',
      'UPDATE +203.0.113.0/24',
      'UPDATE +198.51.100.0/24',
      'End-of-RIB IPv4',
      'End-of-RIB IPv4',
      'UPDATE -203.0.113.0/24',
    ]);

    // TCP steps are visible initially and can be hidden via toggle
    const tcpOptions = page.locator('[data-step-kind="tcp"]');
    expect(await tcpOptions.count()).toBeGreaterThan(0);
    await page.getByLabel('Show TCP steps').uncheck();
    await expect(tcpOptions).toHaveCount(0);
    await expect(bgpOptions).toHaveCount(9);
  });

  test('toggling 4-octet AS off on one side with ASN 65551 shows My AS 23456 and AS_TRANS explanation', async ({
    page,
  }) => {
    await page.goto('/');

    const routerAAsn = page.getByLabel('Router A ASN');
    await routerAAsn.fill('65551');

    const routerBAs4 = page.getByLabel('Router B 4-octet AS');
    await routerBAs4.uncheck();

    // Select Router A's OPEN step on the ladder
    const openA = page.locator('[data-step-kind="bgp"]').first();
    await openA.click();

    const inspector = page.getByRole('region', { name: 'Message Inspector' });
    await expect(inspector).toContainText('My Autonomous System');
    await expect(inspector).toContainText('23456');
    await expect(inspector).toContainText('AS_TRANS');
  });

  test('turning MP IPv6 off on one side removes the IPv6 route from the ladder and shows an explanation', async ({
    page,
  }) => {
    await page.goto('/');

    // Enable MP IPv6 on both sides and add an IPv6 route on Router A
    await page.getByLabel('Router A MP IPv6 Unicast').check();
    await page.getByLabel('Router B MP IPv6 Unicast').check();
    await page.getByRole('button', { name: 'Router A Add IPv6 Route' }).click();

    const ladder = page.getByRole('region', { name: 'Session Ladder' });
    await expect(ladder).toContainText('2001:db8:');

    // Now turn MP IPv6 off on Router B -> IPv6 UPDATE arrow disappears and explanation appears
    await page.getByLabel('Router B MP IPv6 Unicast').uncheck();

    const bgpLabels = await page
      .locator('[data-step-kind="bgp"] .bgp-step-label')
      .allTextContents();
    expect(bgpLabels.some((l) => l.includes('2001:db8:'))).toBe(false);

    const omissions = page.getByRole('status', { name: 'Unsent Routes' });
    await expect(omissions).toBeVisible();
    await expect(omissions).toContainText('2001:db8:');
    await expect(omissions).toContainText('MP IPv6 Unicast');
  });

  test('downloads a non-empty .pcap file with valid libpcap magic number', async ({ page }) => {
    await page.goto('/');

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: 'Download .pcap' }).click(),
    ]);

    const filePath = await download.path();
    expect(filePath).not.toBeNull();
    const bytes = readFileSync(filePath!);
    expect(bytes.length).toBeGreaterThan(24 + 16);

    // Classic little-endian libpcap magic number 0xa1b2c3d4 -> d4 c3 b2 a1
    expect(bytes.readUInt32LE(0)).toBe(0xa1b2c3d4);
  });

  test('standalone Decode BGP hex panel dissects raw hex without a session', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Decode BGP hex' }).click();

    const decoderPanel = page.getByRole('region', { name: 'Decode BGP Hex' });
    await expect(decoderPanel).toBeVisible();
    await expect(decoderPanel).toContainText('BGP OPEN Message');
    await expect(decoderPanel).toContainText('23456');
  });
});
