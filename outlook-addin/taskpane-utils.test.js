const test = require("node:test");
const assert = require("node:assert/strict");
const utils = require("./taskpane-utils.js");

test("escapes untrusted HTML", () => assert.equal(utils.escapeHtml('<script>"x"</script>'), "&lt;script&gt;&quot;x&quot;&lt;/script&gt;"));
test("maps fallback risk levels", () => {
  assert.equal(utils.normalizeThreatLevel({ risk_score: 10 }).code, "safe");
  assert.equal(utils.normalizeThreatLevel({ risk_score: 60 }).code, "high_risk");
});
test("maps verdict classes", () => assert.equal(utils.verdictClassName("Suspicious"), "verdict-suspicious"));
test("report omits AI-only indicators", () => {
  const text = utils.buildReportText({ verdict: "Suspicious", risk_score: 40, threat_level: { label: "Suspicious" }, threat_categories: [], indicators: [{ code: "ai_phishing_signal", severity: "medium", message: "hidden" }] });
  assert.equal(text.includes("hidden"), false);
});
