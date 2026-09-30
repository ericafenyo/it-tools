import { expect, test } from '@playwright/test';

test.describe('Tool - JWT encoder', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/jwt-encoder');
  });

  test('Has correct title', async ({ page }) => {
    await expect(page).toHaveTitle('JWT encoder - IT Tools');
  });

  test('Encodes the default header and payload with HS256', async ({ page }) => {
    await expect(page.getByText('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')).toBeVisible();
  });
});
