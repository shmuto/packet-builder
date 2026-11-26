import { expect, test } from './fixtures';

function toBase64Url(text: string): string {
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

test.describe('Shareable permalinks', () => {
  test('restores a manual corrupted checksum override with identical hex dump in a new page', async ({
    context,
    page,
  }) => {
    await page.goto('/');

    // Select UDP Packet preset explicitly
    await page.getByRole('button', { name: 'UDP Packet', exact: true }).click();
    await expect(page.locator('.hexdump-grid')).toBeVisible();

    // Switch IPv4 Header Checksum to Manual and enter a corrupted value (0xdead = 57005)
    const ipv4Card = page.getByRole('region', { name: 'IPv4 layer' });
    await ipv4Card
      .getByRole('group', { name: 'Header Checksum mode' })
      .getByRole('button', { name: 'Manual', exact: true })
      .click();
    const checksumInput = ipv4Card.getByRole('textbox', { name: 'Header Checksum', exact: true });
    await checksumInput.fill('0xdead');

    // Verify the corrupted 2-byte IPv4 Header Checksum (offsets 24..25 = 14B Ethernet + 10B IPv4)
    const hexBytes = page.locator('.hexdump-grid .hex-byte');
    await expect(hexBytes.nth(24)).toHaveText('de');
    await expect(hexBytes.nth(25)).toHaveText('ad');
    await page.waitForFunction(() => {
      const hash = window.location.hash;
      if (!hash.startsWith('#p1=')) return false;
      const b64 = hash.slice(4).replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
      return atob(padded).includes('57005');
    });

    const expectedHexDump = await page.locator('.hexdump-grid').innerText();
    const sharedUrl = page.url();

    // Open the permalink in a fresh page and confirm the hex dump matches identically
    const restoredPage = await context.newPage();
    await restoredPage.goto(sharedUrl);
    await expect(restoredPage.locator('.hexdump-grid')).toBeVisible();
    await expect(
      restoredPage
        .getByRole('region', { name: 'IPv4 layer' })
        .getByRole('textbox', { name: 'Header Checksum', exact: true }),
    ).toHaveValue('0xdead');
    await expect(restoredPage.locator('.hexdump-grid')).toHaveText(expectedHexDump, {
      useInnerText: true,
    });
    await restoredPage.close();
  });

  test('rejects malformed permalink #p1=!!! with Invalid Permalink banner and falls back to default preset', async ({
    page,
  }) => {
    await page.goto('/#p1=!!!');

    const banner = page.locator('.permalink-error-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('Invalid Permalink');

    // Default UDP Packet preset is loaded cleanly
    await expect(page.getByRole('button', { name: 'UDP Packet', exact: true })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await expect(page.locator('.layer-card .layer-name')).toHaveText([
      'Ethernet II',
      'IPv4',
      'UDP',
      'Payload',
    ]);
    await expect(page.locator('.hexdump-grid')).toBeVisible();
  });

  test('rejects prototype-pollution payload {"__proto__":{"x":1}} with Invalid Permalink banner', async ({
    page,
  }) => {
    const maliciousFragment = `#p1=${toBase64Url('{"__proto__":{"x":1}}')}`;
    await page.goto(`/${maliciousFragment}`);

    const banner = page.locator('.permalink-error-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('Invalid Permalink');

    await expect(page.getByRole('button', { name: 'UDP Packet', exact: true })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await expect(page.locator('.layer-card .layer-name')).toHaveText([
      'Ethernet II',
      'IPv4',
      'UDP',
      'Payload',
    ]);
    await expect(page.locator('.hexdump-grid')).toBeVisible();
    expect(await page.evaluate(() => ({} as { x?: unknown }).x)).toBeUndefined();
  });
});
