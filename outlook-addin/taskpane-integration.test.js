const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const utils = require("./taskpane-utils.js");

function element() {
  return {
    hidden: true,
    textContent: "",
    innerHTML: "",
    disabled: false,
    addEventListener() {},
    insertAdjacentHTML() {},
    remove() {},
  };
}

test("phishing report explains model evidence instead of reassuring fallback reasons", () => {
  const elements = new Map(["scanButton", "historyButton", "result", "connectionStatus", "runtimeNote"].map(id => [id, element()]));
  const context = {
    URLSearchParams, setTimeout, clearTimeout, AbortController,
    window: { location: { search: "", pathname: "/addin/taskpane.html", origin: "https://localhost:8000" }, UniPhishGuardUtils: utils },
    document: { getElementById: id => elements.get(id) || null },
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync("taskpane.js", "utf8"), context);
  context.report = {
    verdict: "Likely phishing", risk_score: 55, ai_prediction: "phishing", ai_confidence: 0.998,
    top_reasons: ["AI text analysis found phishing-like wording (100%).", "AI noticed: account"],
    indicators: [{ code: "ai_phishing_signal", severity: "high", message: "AI text analysis found phishing-like wording (100%)." }],
    attachment_content_status: "checked",
  };
  const reasons = vm.runInContext("buildResultReasons(report, buildCheckStatuses(report))", context);
  assert.match(reasons[0], /AI text analysis/);
  assert.equal(reasons.some(reason => /No suspicious|No known/.test(reason)), false);
  vm.runInContext("renderReport(report)", context);
  assert.match(elements.get("result").innerHTML, /AI text analysis found phishing-like wording/);

  // Authenticated senders may lack an AI indicator while the score still
  // includes the model. They also need an explanation of the warning.
  context.report.indicators = [];
  assert.match(vm.runInContext("buildResultReasons(report, [])[0]", context), /AI text analysis/);

  context.report.top_reasons = ["University account link opens outside.example, outside approved domains."];
  assert.match(vm.runInContext("buildResultReasons(report, [])[0]", context), /outside.example/);
});

test("sample requires explicit opt-in; missing mailbox never silently scans demo data", async () => {
  const elements = new Map(
    ["scanButton", "historyButton", "result", "connectionStatus", "runtimeNote"].map((id) => [id, element()]),
  );
  const office = {
    context: {},
    HostType: { Outlook: "Outlook" },
    onReady(callback) {
      callback({ host: null });
      return Promise.resolve();
    },
  };
  const context = {
    console,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    AbortController,
    Office: office,
    window: {
      location: { search: "", pathname: "/addin/taskpane.html", origin: "https://localhost:8000" },
      UniPhishGuardUtils: utils,
      uniphishguardOfficeReady: Promise.resolve({ host: null }),
      uniphishguardOfficeInfo: { host: null },
      Office: office,
    },
    document: { getElementById: (id) => elements.get(id) || null },
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync("taskpane.js", "utf8"), context);

  vm.runInContext("waitForCurrentItem = async () => null", context);
  await assert.rejects(vm.runInContext("getCurrentEmail()", context), /did not expose/);

  // Even with a missing host label, an actual mailbox must supply the message.
  office.CoercionType = { Text: "text", Html: "html" };
  office.AsyncResultStatus = { Succeeded: "succeeded" };
  office.context.mailbox = { item: {
    subject: "New sign-in detected on your Vercel account",
    from: { displayName: "Vercel", emailAddress: "notifications@vercel.com" },
    body: { getAsync(type, callback) { callback({ status: "succeeded", value: "A new sign-in was detected." }); } },
    attachments: [],
  } };
  vm.runInContext("waitForCurrentItem = async () => window.Office.context.mailbox.item", context);
  const realEmail = await vm.runInContext("getCurrentEmail()", context);
  assert.equal(realEmail.subject, office.context.mailbox.item.subject);
  assert.equal(realEmail.sender.email, "notifications@vercel.com");
  assert.equal(realEmail.body, "A new sign-in was detected.");
  assert.equal(JSON.stringify(realEmail).includes("192.168.1.10"), false);
});

test("explicit sample mode returns the demo email", async () => {
  const elements = new Map(["scanButton", "historyButton", "result", "connectionStatus", "runtimeNote"].map(id => [id, element()]));
  const context = {
    URLSearchParams, setTimeout, clearTimeout, AbortController,
    window: { location: { search: "?sample=1", pathname: "/addin/taskpane.html", origin: "https://localhost:8000" }, UniPhishGuardUtils: utils },
    document: { getElementById: id => elements.get(id) || null },
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync("taskpane.js", "utf8"), context);

  const email = await vm.runInContext("getCurrentEmail()", context);
  assert.match(email.subject, /password verification/i);
  assert.equal(elements.get("runtimeNote").hidden, false);
  assert.match(elements.get("runtimeNote").textContent, /built-in sample/i);
});
