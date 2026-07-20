const { expect, test } = require("@playwright/test");

test("browser preview scans sample email and renders a phishing report", async ({ page }) => {
  await page.goto("/addin/taskpane.html");

  await page.getByRole("button", { name: "Scan Email" }).click();

  await expect(page.getByRole("heading", { name: /phishing|suspicious/i })).toBeVisible();
  await expect(page.locator(".score")).toContainText(/\d+/);
  await expect(page.getByText("Why This Result?")).toBeVisible();
  await expect(page.getByText(/deceptive double extension|high-risk extension/i)).toBeVisible();
});

test("history button renders recent scans", async ({ page }) => {
  await page.goto("/addin/taskpane.html");

  await page.getByRole("button", { name: "Scan Email" }).click();
  await expect(page.locator(".score")).toBeVisible();

  await page.getByRole("button", { name: "History" }).click();

  await expect(page.getByText("Recent Scans")).toBeVisible();
  await expect(page.locator(".history-list li").first()).toBeVisible();
});

test("shows a clear backend offline error", async ({ page }) => {
  await page.route("**/health", (route) => route.abort());
  await page.goto("/addin/taskpane.html");

  await page.getByRole("button", { name: "Scan Email" }).click();

  await expect(page.getByText("Backend offline.")).toBeVisible();
  await expect(page.getByText("Code: BACKEND_OFFLINE")).toBeVisible();
});
