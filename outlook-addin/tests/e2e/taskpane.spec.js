const { expect, test } = require("@playwright/test");

test("browser preview scans sample email and renders a phishing report", async ({ page }) => {
  await page.goto("/addin/taskpane.html?sample=1");

  await page.getByRole("button", { name: "Scan Email" }).click();

  await expect(page.getByRole("heading", { name: /phishing|suspicious/i })).toBeVisible();
  await expect(page.locator(".score")).toContainText(/\d+/);
  await expect(page.getByText("Score Breakdown")).toBeVisible();
  await expect(page.getByText("AI Language Assessment")).toBeVisible();
  await expect(page.locator("text=Attachment Analysis").first()).toBeVisible();
  await expect(page.locator("text=deceptive double extension").first()).toBeVisible();
});

test("history button renders recent scans", async ({ page }) => {
  await page.goto("/addin/taskpane.html?sample=1");

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
