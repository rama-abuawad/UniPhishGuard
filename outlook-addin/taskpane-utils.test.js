const test = require("node:test");
const assert = require("node:assert/strict");
const utils = require("./taskpane-utils.js");

test("escapes untrusted HTML", () => assert.equal(utils.escapeHtml('<script>"x"</script>'), "&lt;script&gt;&quot;x&quot;&lt;/script&gt;"));
test("maps fallback risk levels", () => {
  assert.equal(utils.normalizeThreatLevel({ risk_score: 10 }).code, "low_risk");
  assert.equal(utils.normalizeThreatLevel({ risk_score: 60 }).code, "high_risk");
});
test("limits attachment retrieval to supported bounded items", () => {
  assert.equal(utils.attachmentCanBeRetrieved({ id: "a", size: 100 }, 1000), true);
  assert.equal(utils.attachmentCanBeRetrieved({ id: "a", size: 1001 }, 1000), false);
  assert.equal(utils.attachmentCanBeRetrieved({ size: 100 }, 1000), false);
});
test("accepts base64 attachment content and rejects non-base64 formats", () => {
  assert.equal(utils.base64Content({ format: "Base64", content: "YWJj\n" }), "YWJj");
  assert.equal(utils.base64Content({ format: "Eml", content: "Subject: test" }), null);
  assert.equal(utils.base64Content({ format: "Eml", content: "YWJj" }), null);
});
test("maps verdict classes", () => assert.equal(utils.verdictClassName("Suspicious"), "verdict-suspicious"));
test("report omits AI-only indicators", () => {
  const text = utils.buildReportText({ verdict: "Suspicious", risk_score: 40, ai_confidence: 0.99, threat_level: { label: "Suspicious" }, threat_categories: [], indicators: [{ code: "ai_phishing_signal", severity: "medium", message: "hidden" }] });
  assert.equal(text.includes("hidden"), false);
  assert.equal(text.includes("ML phishing probability"), false);
  assert.equal(text.includes("99%"), false);
});
test("untrusted authentication is never shown as passed", () => {
  const status = utils.inspectionStatuses({ authentication_status: "untrusted", indicators: [] })[0];
  assert.equal(status.value, "Could not be verified");
});
test("unavailable attachment bytes are not described as safe", () => {
  const status = utils.inspectionStatuses({ authentication_status: "not_available", attachment_content_status: "not_available", indicators: [] })[2];
  assert.equal(status.value, "Content inspection unavailable");
});
test("report displays the user-facing risk score", () => {
  const text = utils.buildReportText({ verdict: "Low Risk", risk_score: 4, analysis_completeness: "partial", analysis_limitations: ["Headers unavailable"], threat_level: { label: "Low Risk" }, indicators: [] });
  assert.equal(text.includes("Risk score: 4/100"), true);
  assert.equal(text.includes("not a probability"), false);
  assert.equal(text.includes("Headers unavailable"), true);
});
