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
});
