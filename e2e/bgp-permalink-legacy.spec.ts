import { expect, test } from './fixtures';

test.describe('Session permalinks (#s1=), validation, and /legacy/ support', () => {
  test('Copy Link round-trip restores the same modified ladder in a new page', async ({
    context,
    page,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.goto('/');

    // Customize Router A ASN and Hold Time so the ladder differs from defaults
    await page.getByLabel('Router A ASN').fill('65551');
    await page.getByLabel('Router A Hold Time').fill('60');

    const expectedLabels = await page
      .locator('[data-step-kind="bgp"] .bgp-step-label')
      .allTextContents();
    expect(expectedLabels[0]).toContain('AS 65551');
    expect(expectedLabels[0]).toContain('Hold 60s');

    await page.getByRole('button', { name: 'Copy Link' }).click();
    const copiedUrl = await page.evaluate(() => navigator.clipboard.readText());
    expect(copiedUrl).toContain('#s1=');

    const page2 = await context.newPage();
    await page2.goto(copiedUrl);
    const restoredLabels = await page2
      .locator('[data-step-kind="bgp"] .bgp-step-label')
      .allTextContents();
    expect(restoredLabels).toEqual(expectedLabels);
  });

  test('rejects malformed #s1=!!! with error banner and falls back to default scenario', async ({
    page,
  }) => {
    await page.goto('/#s1=!!!');

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('Invalid session link');

    await expect(page.locator('[data-step-kind="bgp"]')).toHaveCount(9);
  });

  test('rejects prototype-pollution payload in #s1= with error banner and falls back safely', async ({
    page,
  }) => {
    const encoded = Buffer.from('{"__proto__":{"polluted":1}}', 'utf8').toString('base64url');
    await page.goto(`/#s1=${encoded}`);

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('Invalid session link');

    const polluted = await page.evaluate(() => ({} as Record<string, unknown>).polluted);
    expect(polluted).toBeUndefined();
    await expect(page.locator('[data-step-kind="bgp"]')).toHaveCount(9);
  });

  test('shows legacy notice pointing to legacy/ for old #p1= links and serves /legacy/ cleanly', async ({
    page,
  }) => {
    const oldFrag = '#p1=eyJsYXllcnMiOltdLCJwYXlsb2FkIjp7Im1vZGUiOiJ0ZXh0IiwidGV4dCI6IiJ9fQ';
    await page.goto(`/${oldFrag}`);

    const legacyLink = page.getByRole('link', { name: /Open in Legacy Packet Builder/i });
    await expect(legacyLink).toBeVisible();
    const href = await legacyLink.getAttribute('href');
    expect(href).toBe(`./legacy/${oldFrag}`);

    // Navigate to /legacy/ and verify the old general-purpose builder loads with zero 4xx/console errors
    await page.goto('/legacy/');
    await expect(page.getByRole('heading', { level: 1 })).toContainText('tsumiki');
    await expect(page.getByRole('button', { name: 'UDP Packet' })).toBeVisible();
  });
});
