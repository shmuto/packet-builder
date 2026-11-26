import { expect, test } from './fixtures';

const VIEWPORT_WIDTHS = [360, 390, 768, 1040, 1100, 1280] as const;

test.describe('Responsive layout', () => {
  test('every preset has zero page horizontal overflow across all widths and zero hex-dump scroll at 1100px and 1280px', async ({
    page,
  }) => {
    await page.goto('/');
    await expect(page.locator('.hexdump-box')).toBeVisible();

    const presetButtons = page.locator('.preset-list .preset-btn:not(.is-import)');
    const presetCount = await presetButtons.count();
    expect(presetCount).toBeGreaterThanOrEqual(8);

    const presetNames: string[] = [];
    for (let i = 0; i < presetCount; i++) {
      presetNames.push((await presetButtons.nth(i).innerText()).trim());
    }

    for (const width of VIEWPORT_WIDTHS) {
      await page.setViewportSize({ width, height: 900 });

      for (let i = 0; i < presetCount; i++) {
        const name = presetNames[i];
        await presetButtons.nth(i).click();
        await expect(presetButtons.nth(i)).toHaveAttribute('aria-pressed', 'true');
        await expect(page.locator('.hexdump-box')).toBeVisible();

        const metrics = await page.evaluate(() => {
          const docScrollWidth = document.documentElement.scrollWidth;
          const innerWidth = window.innerWidth;
          const box = document.querySelector('.hexdump-box');
          return {
            docScrollWidth,
            innerWidth,
            boxScrollWidth: box ? box.scrollWidth : -1,
            boxClientWidth: box ? box.clientWidth : -1,
          };
        });

        expect(
          metrics.docScrollWidth,
          `Page horizontal overflow for preset "${name}" at width ${width}px`,
        ).toBeLessThanOrEqual(metrics.innerWidth);

        if (width === 1100 || width === 1280) {
          expect(
            metrics.boxClientWidth,
            `.hexdump-box missing or collapsed for preset "${name}" at width ${width}px`,
          ).toBeGreaterThan(0);
          expect(
            metrics.boxScrollWidth,
            `.hexdump-box horizontal scroll for preset "${name}" at width ${width}px`,
          ).toBeLessThanOrEqual(metrics.boxClientWidth);
        }
      }
    }
  });
});
