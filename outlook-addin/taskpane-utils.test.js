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
test("exported report retains the text-model reason for a warning", () => {
  const text = utils.buildReportText({ verdict: "Likely phishing", risk_score: 55, threat_level: { label: "High Risk" }, indicators: [{ code: "ai_phishing_signal", severity: "high", message: "AI text analysis found phishing-like wording." }] });
  assert.match(text, /AI text analysis found phishing-like wording/);
  assert.equal(text.includes("No major indicators found"), false);
});

test("all URL warning codes are reflected in link status", () => {
  for (const code of ["url_university_account_external", "encoded_url", "punycode_domain", "suspicious_url_domain"]) {
    const status = utils.inspectionStatuses({ indicators: [{ code, severity: "medium" }] })[1];
    assert.equal(status.tone, "warning", code);
  }
});

test("an unmatched URL rule does not claim destination safety", () => {
  const status = utils.inspectionStatuses({ indicators: [] })[1];
  assert.equal(status.tone, "neutral");
  assert.match(status.value, /destination safety was not verified/);
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
