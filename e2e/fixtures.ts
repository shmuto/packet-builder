import { test as base, expect, type ConsoleMessage, type Page, type Response } from '@playwright/test';

/**
 * Shared Playwright test fixture that automatically fails any test if an uncaught
 * `pageerror`, `console.error`, or same-origin HTTP error (status >= 400) occurs
 * on any page within the browser context.
 */
export const test = base.extend<{ failOnBrowserErrors: void }>({
  failOnBrowserErrors: [
    async ({ context, page, baseURL }, use) => {
      const errors: string[] = [];
      const attached = new WeakSet<Page>();
      const baseOrigin = baseURL ? new URL(baseURL).origin : null;

      const isSameOrigin = (responseUrl: string, target: Page): boolean => {
        try {
          const responseOrigin = new URL(responseUrl).origin;
          if (baseOrigin) {
            return responseOrigin === baseOrigin;
          }
          const pageUrl = target.url();
          if (pageUrl && pageUrl !== 'about:blank') {
            return responseOrigin === new URL(pageUrl).origin;
          }
          return false;
        } catch {
          return false;
        }
      };

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
        target.on('response', (res: Response) => {
          if (res.status() >= 400 && isSameOrigin(res.url(), target)) {
            errors.push(`HTTP ${res.status()}: ${res.url()}`);
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
