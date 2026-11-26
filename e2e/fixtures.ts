import { test as base, expect, type ConsoleMessage, type Page } from '@playwright/test';

/**
 * Shared Playwright test fixture that automatically fails any test if an uncaught
 * `pageerror` or `console.error` occurs on any page within the browser context.
 */
export const test = base.extend<{ failOnBrowserErrors: void }>({
  failOnBrowserErrors: [
    async ({ context, page }, use) => {
      const errors: string[] = [];
      const attached = new WeakSet<Page>();

      const attachListeners = (target: Page) => {
        if (attached.has(target)) return;
        attached.add(target);
        target.on('pageerror', (err: Error) => {
          errors.push(`pageerror: ${err.message}`);
        });
        target.on('console', (msg: ConsoleMessage) => {
          if (msg.type() === 'error') {
            errors.push(`console.error: ${msg.text()}`);
          }
        });
      };

      attachListeners(page);
      for (const existing of context.pages()) {
        attachListeners(existing);
      }
      context.on('page', attachListeners);

      await use();

      expect(errors, `Unexpected browser errors:\n${errors.join('\n')}`).toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
