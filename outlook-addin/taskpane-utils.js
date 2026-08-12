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
    return { code: "low_risk", label: "Low Risk", color: "#1f7a4d" };
  }

  function attachmentCanBeRetrieved(attachment, maximumBytes) {
    if (!attachment || !attachment.id) return false;
    if (Number(attachment.size) > maximumBytes) return false;
    return true;
  }

  function base64Content(value) {
    if (!value || typeof value.content !== "string") return null;
    const format = String(value.format || "").toLowerCase();
    if (format && !format.includes("base64")) return null;
    return /^[a-z0-9+/=\r\n]+$/i.test(value.content) ? value.content.replace(/\s+/g, "") : null;
  }

  function inspectionStatuses(report) {
    const indicators = report.indicators || [];
    const important = (...prefixes) => indicators.some((indicator) =>
      ["high", "medium"].includes(indicator.severity) && prefixes.some((prefix) => indicator.code.startsWith(prefix))
    );
    const authentication = {
      passed: { value: "Passed", tone: "safe" }, failed: { value: "Failed", tone: "warning" },
      untrusted: { value: "Could not be verified", tone: "warning" }, not_available: { value: "Not available", tone: "neutral" },
    }[report.authentication_status] || { value: "Not available", tone: "neutral" };
    const attachmentWarning = important("attachment", "double_extension", "dangerous_attachment", "macro_", "archive_", "zip_", "qr_");
    const attachmentAvailability = report.attachment_content_status || "not_requested";
    return [
      { label: "Sender authentication", ...authentication },
      { label: "Links", value: important("url_", "link_", "approved_domain") ? "Suspicious patterns detected" : "No suspicious link patterns detected", tone: important("url_", "link_", "approved_domain") ? "warning" : "safe" },
      {
        label: "Attachments",
        value: attachmentWarning ? "Suspicious patterns detected" : attachmentAvailability === "checked" ? "No suspicious attachment patterns detected" : attachmentAvailability === "partial" ? "Partially inspected" : "Content inspection unavailable",
        tone: attachmentWarning ? "warning" : attachmentAvailability === "checked" ? "safe" : "neutral",
      },
    ];
  }

  function buildReportText(report) {
    const threatLevel = report.threat_level || { label: "Unknown" };
    const categories = (report.threat_categories || []).length
      ? report.threat_categories.map((category) => `- ${category.label} (${categoryEvidence(category)} evidence)`).join("\n")
      : "- No specific category detected";
    const important = (report.indicators || []).filter((indicator) => indicator.code !== "ai_phishing_signal" && ["high", "medium"].includes(indicator.severity));
    const indicators = important.length ? important.map((indicator) => `- ${indicator.message}`).join("\n") : "- No major indicators found";
    return ["UniPhishGuard report", `Scan ID: ${report.scan_id || "Unavailable"}`, `Verdict: ${report.verdict}`, `Threat level: ${threatLevel.label}`, `Risk score: ${report.risk_score}/100`, "Threat categories:", categories, "Indicators:", indicators].join("\n");
  }

  return { attachmentCanBeRetrieved, base64Content, buildReportText, categoryEvidence, escapeHtml, inspectionStatuses, normalizeThreatLevel, verdictClassName };
});
