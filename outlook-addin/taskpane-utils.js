(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.UniPhishGuardUtils = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  function escapeHtml(value) {
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  function categoryEvidence(category) {
    return category.evidence_strength || category.confidence || "medium";
  }

  function verdictClassName(verdict) {
    const normalized = String(verdict).toLowerCase();
    if (normalized.includes("high-risk")) return "verdict-high";
    if (normalized.includes("phishing")) return "verdict-phishing";
    if (normalized.includes("suspicious")) return "verdict-suspicious";
    return "verdict-legitimate";
  }

  function normalizeThreatLevel(report) {
    if (report.threat_level) return report.threat_level;
    const score = Number(report.risk_score) || 0;
    if (score >= 80) return { code: "critical", label: "Critical", color: "#c93232" };
    if (score >= 55) return { code: "high_risk", label: "High Risk", color: "#d45500" };
    if (score >= 25) return { code: "suspicious", label: "Suspicious", color: "#c87816" };
    return { code: "safe", label: "Safe", color: "#1f7a4d" };
  }

  function buildReportText(report) {
    const threatLevel = report.threat_level || { label: "Unknown" };
    const categories = report.risk_score >= 25 && (report.threat_categories || []).length
      ? report.threat_categories.map((category) => `- ${category.label} (${categoryEvidence(category)} evidence)`).join("\n")
      : "- No specific category detected";
    const important = (report.indicators || []).filter((indicator) => indicator.code !== "ai_phishing_signal" && ["high", "medium"].includes(indicator.severity));
    const indicators = important.length ? important.map((indicator) => `- ${indicator.message}`).join("\n") : "- No major indicators found";
    return ["UniPhishGuard report", `Verdict: ${report.verdict}`, `Threat level: ${threatLevel.label}`, `Risk score: ${report.risk_score}/100`, "Threat categories:", categories, "Indicators:", indicators].join("\n");
  }

  return { buildReportText, categoryEvidence, escapeHtml, normalizeThreatLevel, verdictClassName };
});
