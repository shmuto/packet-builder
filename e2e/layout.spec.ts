import { expect, test } from './fixtures';

const VIEWPORT_WIDTHS = [360, 390, 768, 1040, 1100, 1280, 1440] as const;

test.describe('Responsive layout', () => {
  test('serves a valid favicon linked from index.html (200 OK)', async ({ page }) => {
    await page.goto('/');
    const href = await page.locator('link[rel="icon"]').getAttribute('href');
    expect(href).toBeTruthy();
    const res = await page.request.get(new URL(href!, page.url()).toString());
    expect(res.status()).toBe(200);
  });

  test('displays 4 labeled preset groups with Basics first at 1440px and <=2 rows at 390px, with Import Hex in export toolbar', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');

    const groups = page.locator('.preset-group');
    await expect(groups).toHaveCount(4);
    for (let i = 0; i < 4; i++) {
      await expect(groups.nth(i)).toBeVisible();
    }
    await expect(page.locator('.preset-group-title')).toHaveText([
      'Basics',
      'IPv6',
      'Tunnels & Overlays',
      'Advanced',
    ]);
    await expect(groups.first()).toHaveClass(/is-primary/);

    // Import Hex belongs in the export toolbar, not in the preset bar
    await expect(page.locator('.preset-bar').getByRole('button', { name: 'Import Hex' })).toHaveCount(0);
    await expect(page.locator('.export-toolbar').getByRole('button', { name: 'Import Hex' })).toBeVisible();

    // At 390px before any interaction, only Basics is expanded and the preset area takes <= 2 rows
    await page.setViewportSize({ width: 390, height: 900 });
    await page.goto('/');

    await expect(page.locator('#preset-group-select')).toBeVisible();
    await expect(page.locator('#preset-group-select')).toHaveValue('basics');
    await expect(page.locator('.preset-group[data-preset-group="basics"]')).toBeVisible();
    await expect(page.locator('.preset-group[data-preset-group="ipv6"]')).toBeHidden();
    await expect(page.locator('.preset-group[data-preset-group="tunnels"]')).toBeHidden();
    await expect(page.locator('.preset-group[data-preset-group="advanced"]')).toBeHidden();

    const mobileMetrics = await page.evaluate(() => {
      const select = document.querySelector('#preset-group-select');
      const visibleBtns = Array.from(document.querySelectorAll('.preset-group.is-mobile-active .preset-btn'));
      const rowTops = new Set<number>();
      if (select) {
        rowTops.add(Math.round(select.getBoundingClientRect().top / 8));
      }
      for (const btn of visibleBtns) {
        rowTops.add(Math.round(btn.getBoundingClientRect().top / 8));
      }
      return {
        rowCount: rowTops.size,
        docScrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
      };
    });

    expect(mobileMetrics.rowCount).toBeLessThanOrEqual(2);
    expect(mobileMetrics.docScrollWidth).toBeLessThanOrEqual(mobileMetrics.innerWidth);
  });

  test('every preset has zero page horizontal overflow across all widths and zero hex-dump scroll at 1100px and 1280px', async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await expect(page.locator('.hexdump-box')).toBeVisible();

    const presetButtons = page.locator('.preset-group .preset-btn');
    const presetCount = await presetButtons.count();
    expect(presetCount).toBeGreaterThanOrEqual(11);

    const presetsMeta: { name: string; group: string }[] = [];
    for (let i = 0; i < presetCount; i++) {
      const btn = presetButtons.nth(i);
      const name = (await btn.innerText()).trim();
      const group = await btn.evaluate(
        (el) => el.closest('.preset-group')?.getAttribute('data-preset-group') ?? '',
      );
      presetsMeta.push({ name, group });
    }

    const mobileSelect = page.locator('#preset-group-select');

    for (const width of VIEWPORT_WIDTHS) {
      await page.setViewportSize({ width, height: 900 });
      const isCompact = await mobileSelect.isVisible();

      for (let i = 0; i < presetCount; i++) {
        const { name, group } = presetsMeta[i];
        if (isCompact) {
          await mobileSelect.selectOption(group);
        }
        const btn = presetButtons.nth(i);
        await btn.click();
        await expect(btn).toHaveAttribute('aria-pressed', 'true');
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
