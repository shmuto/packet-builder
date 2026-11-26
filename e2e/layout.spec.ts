import { expect, test } from './fixtures';

const VIEWPORT_WIDTHS = [360, 390, 768, 1040, 1100, 1280] as const;

test.describe('Responsive layout', () => {
  test('serves a valid favicon linked from index.html (200 OK)', async ({ page }) => {
    await page.goto('/');
    const href = await page.locator('link[rel="icon"]').getAttribute('href');
    expect(href).toBeTruthy();
    const res = await page.request.get(new URL(href!, page.url()).toString());
    expect(res.status()).toBe(200);
  });

  test('exposes Open Graph / Twitter tags, serves og.png (200 OK), and renders the footer issue link', async ({
    page,
  }) => {
    await page.goto('/');

    const meta = async (selector: string) => page.locator(selector).getAttribute('content');
    expect(await meta('meta[property="og:title"]')).toBeTruthy();
    expect(await meta('meta[property="og:description"]')).toBeTruthy();
    expect(await meta('meta[property="og:type"]')).toBe('website');
    expect(await meta('meta[property="og:url"]')).toBe('https://shmuto.github.io/packet-builder/');
    const ogImage = await meta('meta[property="og:image"]');
    expect(ogImage).toBe('https://shmuto.github.io/packet-builder/og.png');
    expect(await meta('meta[name="twitter:card"]')).toBe('summary_large_image');
    expect(await meta('meta[name="theme-color"]')).toBeTruthy();

    const ogFilename = new URL(ogImage!).pathname.split('/').pop();
    const res = await page.request.get(new URL(ogFilename!, page.url()).toString());
    expect(res.status()).toBe(200);
    expect(res.headers()['content-type']).toContain('image/png');

    const issueLink = page.getByRole('link', { name: 'Report an issue' });
    await expect(issueLink).toBeVisible();
    await expect(issueLink).toHaveAttribute(
      'href',
      'https://github.com/shmuto/packet-builder/issues/new/choose',
    );
  });

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
