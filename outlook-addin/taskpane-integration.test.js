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
