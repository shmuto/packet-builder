import { expect, test } from './fixtures';

const VIEWPORT_WIDTHS = [360, 390, 768, 1280] as const;

test.describe('Responsive layout for BGP learning UI', () => {
  for (const width of VIEWPORT_WIDTHS) {
    test(`has zero horizontal page overflow at ${width}px width`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto('/');

      await expect(page.locator('[data-step-kind="bgp"]').first()).toBeVisible();

      const overflow = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth,
      }));
      expect(
        overflow.scrollWidth,
        `Horizontal overflow at ${width}px (scrollWidth=${overflow.scrollWidth}, clientWidth=${overflow.clientWidth})`,
      ).toBeLessThanOrEqual(overflow.clientWidth);
    });
  }

  test('exposes Open Graph tags, serves og.png (200 OK), and renders the Report an issue footer link', async ({
    page,
    request,
  }) => {
    await page.goto('/');

    const ogTitle = await page.locator('meta[property="og:title"]').getAttribute('content');
    const ogDesc = await page.locator('meta[property="og:description"]').getAttribute('content');
    const ogType = await page.locator('meta[property="og:type"]').getAttribute('content');
    const ogUrl = await page.locator('meta[property="og:url"]').getAttribute('content');
    const ogImage = await page.locator('meta[property="og:image"]').getAttribute('content');
    const twitterCard = await page.locator('meta[name="twitter:card"]').getAttribute('content');
    const themeColor = await page.locator('meta[name="theme-color"]').getAttribute('content');

    expect(ogTitle).toBe('tsumiki — Learn BGP Messages');
    expect(ogDesc).toBe(
      "Learn what's inside BGP messages — OPEN capabilities, UPDATE attributes, End-of-RIB, and NOTIFICATIONs — before you open your first capture.",
    );
    expect(ogType).toBe('website');
    expect(ogUrl).toBe('https://shmuto.github.io/packet-builder/');
    expect(ogImage).toBe('https://shmuto.github.io/packet-builder/og.png');
    expect(twitterCard).toBe('summary_large_image');
    expect(themeColor).toBe('#2563eb');

    const ogRes = await request.get('/og.png');
    expect(ogRes.status()).toBe(200);
    expect(ogRes.headers()['content-type']).toContain('image/png');

    const reportLink = page.getByRole('link', { name: 'Report an issue' });
    await expect(reportLink).toBeVisible();
    await expect(reportLink).toHaveAttribute(
      'href',
      'https://github.com/shmuto/packet-builder/issues/new/choose',
    );
  });
});
