const assert = require("assert");

const helpers = require("./taskpane.helpers");

function testExtractsHiddenHref() {
  const links = helpers.extractLinks(
    '<p>Open <a href="https://evil.example.com/login">https://students.adu.ac.ae</a></p>',
    "Backup link https://students.adu.ac.ae",
  );

  assert.equal(links[0].text, "https://students.adu.ac.ae");
  assert.equal(links[0].href, "https://evil.example.com/login");
  assert.equal(links.length, 2);
}

function testClassifiesUsefulErrors() {
  assert.equal(helpers.classifyError({ status: 401 }).code, "AUTH_401");
  assert.equal(helpers.classifyError({ status: 413 }).code, "INPUT_413");
  assert.equal(helpers.classifyError({ status: 429 }).code, "RATE_LIMIT");
  assert.equal(helpers.classifyError(new Error("network failed")).code, "BACKEND_OFFLINE");
}

function testEvidenceStrengthFallback() {
  assert.equal(helpers.categoryEvidence({ evidence_strength: "high" }), "high");
  assert.equal(helpers.categoryEvidence({ confidence: "medium" }), "medium");
  assert.equal(helpers.categoryEvidence({}), "medium");
}

function testBuildReportText() {
  const text = helpers.buildReportText({
    verdict: "Likely phishing",
    risk_score: 72,
    ai_confidence: 0.91,
    threat_level: { label: "High Risk" },
    threat_categories: [{ label: "Credential Theft", evidence_strength: "high" }],
    indicators: [{ severity: "high", message: "Link mismatch." }],
  });

  assert(text.includes("Verdict: Likely phishing"));
  assert(text.includes("Credential Theft (high evidence)"));
  assert(text.includes("HIGH: Link mismatch."));
}

testExtractsHiddenHref();
testClassifiesUsefulErrors();
testEvidenceStrengthFallback();
testBuildReportText();

console.log("taskpane helper tests passed");
