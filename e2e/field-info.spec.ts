import { expect, test } from './fixtures';

test.describe('Per-field info controls', () => {
  test('supports click toggle, Escape close, Tab + Enter/Space keyboard activation, and aria-describedby linkage', async ({
    page,
  }) => {
    await page.goto('/');

    const input = page.getByRole('textbox', { name: 'Destination MAC', exact: true });
    const infoButton = page.getByRole('button', { name: 'Explain Destination MAC', exact: true });

    await expect(infoButton).toBeVisible();
    await expect(infoButton).toHaveAttribute('aria-expanded', 'false');

    const docId = await infoButton.getAttribute('aria-controls');
    expect(docId).toBeTruthy();
    const docBox = page.locator(`#${docId}`);
    await expect(docBox).toHaveCount(0);

    // 1. Click opens and links input aria-describedby to the visible summary
    await infoButton.click();
    await expect(infoButton).toHaveAttribute('aria-expanded', 'true');
    await expect(docBox).toBeVisible();
    await expect(docBox).toContainText('IEEE 802.3');
    const describedBy = await input.getAttribute('aria-describedby');
    expect(describedBy?.split(/\s+/)).toContain(docId);

    // Click again closes
    await infoButton.click();
    await expect(infoButton).toHaveAttribute('aria-expanded', 'false');
    await expect(docBox).toHaveCount(0);

    // 2. Escape closes an open field doc
    await infoButton.click();
    await expect(docBox).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(infoButton).toHaveAttribute('aria-expanded', 'false');
    await expect(docBox).toHaveCount(0);

    // 3. Focus via Tab from the preceding interactive control, then open with Enter and Space
    const removeButton = page.getByRole('button', { name: 'Remove Ethernet II' });
    await removeButton.focus();
    await page.keyboard.press('Tab');
    await expect(infoButton).toBeFocused();

    await page.keyboard.press('Enter');
    await expect(infoButton).toHaveAttribute('aria-expanded', 'true');
    await expect(docBox).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(infoButton).toHaveAttribute('aria-expanded', 'false');
    await expect(docBox).toHaveCount(0);
    await expect(infoButton).toBeFocused();

    await page.keyboard.press('Space');
    await expect(infoButton).toHaveAttribute('aria-expanded', 'true');
    await expect(docBox).toBeVisible();
    const describedByAfterSpace = await input.getAttribute('aria-describedby');
    expect(describedByAfterSpace?.split(/\s+/)).toContain(docId);
  });
});
