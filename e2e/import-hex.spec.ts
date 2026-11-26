import { expect, test } from './fixtures';

declare global {
  interface Window {
    __copiedHex?: string;
  }
}

test.describe('Import Hex round-trip', () => {
  test('every built-in preset exports via Copy Hex and decodes back to the exact layer stack and hex dump', async ({
    page,
  }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: {
          writeText: async (text: string) => {
            window.__copiedHex = text;
          },
        },
      });
    });

    await page.goto('/');
    await expect(page.locator('.hexdump-grid')).toBeVisible();

    const presetButtons = page.locator('.preset-list .preset-btn:not(.is-import)');
    const presetCount = await presetButtons.count();
    expect(presetCount).toBeGreaterThanOrEqual(8);

    for (let i = 0; i < presetCount; i++) {
      const btn = presetButtons.nth(i);
      const presetName = (await btn.innerText()).trim();

      await btn.click();
      await expect(btn).toHaveAttribute('aria-pressed', 'true');

      const originalLayers = await page.locator('.layer-card .layer-name').allInnerTexts();
      const originalHexDump = await page.locator('.hexdump-grid').innerText();

      await page.evaluate(() => {
        window.__copiedHex = undefined;
      });
      await page.getByRole('button', { name: /^(Copy Hex|Copied Hex!)$/ }).click();
      const copiedHex = await page.evaluate(() => window.__copiedHex ?? '');
      expect(copiedHex.length, `Copy Hex output for "${presetName}"`).toBeGreaterThan(0);

      // Open Import Hex panel, paste the copied hex, and decode
      const importToggle = page.getByRole('button', { name: 'Import Hex' });
      if ((await importToggle.getAttribute('aria-expanded')) !== 'true') {
        await importToggle.click();
      }
      const textarea = page.getByLabel('Hexadecimal packet bytes');
      await expect(textarea).toBeVisible();
      await textarea.fill(copiedHex);
      await page.getByRole('button', { name: 'Decode & Load' }).click();

      await expect(
        page.locator('.layer-card .layer-name'),
        `Decoded layer stack for "${presetName}"`,
      ).toHaveText(originalLayers);
      await expect(
        page.locator('.hexdump-grid'),
        `Decoded hex dump for "${presetName}"`,
      ).toHaveText(originalHexDump, { useInnerText: true });
    }
  });
});
