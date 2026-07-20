(function (root) {
  function extractLinks(html, text) {
    const links = [];

    if (html && root.DOMParser) {
      const doc = new root.DOMParser().parseFromString(html, "text/html");
      doc.querySelectorAll("a[href]").forEach((anchor) => {
        links.push({
          text: (anchor.textContent || "").trim().slice(0, 500),
          href: anchor.href || anchor.getAttribute("href"),
        });
      });
    } else if (html) {
      const anchorRegex = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
      for (const match of html.matchAll(anchorRegex)) {
        links.push({
          text: stripTags(match[2]).trim().slice(0, 500),
          href: match[1],
        });
      }
    }

    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    for (const match of String(text || "").matchAll(urlRegex)) {
      links.push({ text: match[0], href: match[0] });
    }

    const seen = new Set();
    return links
      .filter((link) => link.href && /^https?:\/\//i.test(link.href))
      .filter((link) => {
        const key = link.href.trim();
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      })
      .slice(0, 100);
  }

  function stripTags(value) {
    return String(value || "").replace(/<[^>]+>/g, " ");
  }

  function categoryEvidence(category) {
    return category.evidence_strength || category.confidence || "medium";
  }

  function buildReportText(report) {
    const threatLevel = report.threat_level || { label: "Unknown" };
    const categories = (report.threat_categories || []).length
      ? report.threat_categories
          .map((category) => `- ${category.label} (${categoryEvidence(category)} evidence)`)
          .join("\n")
      : "- No specific category detected";
    const indicators = (report.indicators || []).length
      ? report.indicators
          .map((indicator) => `- ${String(indicator.severity || "").toUpperCase()}: ${indicator.message}`)
          .join("\n")
      : "- No major indicators found";

    return [
      "UniPhishGuard report",
      `Verdict: ${report.verdict}`,
      `Threat level: ${threatLevel.label}`,
      `Risk score: ${report.risk_score}/100`,
      `AI confidence: ${Math.round((report.ai_confidence || 0) * 100)}%`,
      "Threat categories:",
      categories,
      "Indicators:",
      indicators,
    ].join("\n");
  }

  function classifyError(error) {
    if (error.status === 401 || error.status === 403) {
      return {
        title: "Authentication needed.",
        message: "Sign in or check the configured API token before scanning again.",
        code: `AUTH_${error.status}`,
      };
    }
    if (error.status === 413 || error.status === 422) {
      return {
        title: "Email is too large to scan.",
        message: "Try a smaller message or remove very large metadata before scanning.",
        code: `INPUT_${error.status}`,
      };
    }
    if (error.status === 429) {
      return {
        title: "Too many scans.",
        message: "Wait a minute and try again.",
        code: "RATE_LIMIT",
      };
    }
    if (/certificate|ssl|tls/i.test(error.message || "")) {
      return {
        title: "Certificate problem.",
        message: "Open the backend health URL and accept the local certificate, then scan again.",
        code: "CERTIFICATE",
      };
    }
    if (/not reachable|failed to fetch|network/i.test(error.message || "")) {
      return {
        title: "Backend offline.",
        message: `Start the backend and check https://localhost:8000/health. ${error.message || ""}`.trim(),
        code: "BACKEND_OFFLINE",
      };
    }
    return {
      title: "Scan failed.",
      message: error.message || "Check that the FastAPI backend is running over HTTPS.",
      code: "SCAN_ERROR",
    };
  }

  const helpers = {
    buildReportText,
    categoryEvidence,
    classifyError,
    extractLinks,
  };

  root.UniPhishGuardHelpers = helpers;

  if (typeof module !== "undefined") {
    module.exports = helpers;
  }
})(typeof window !== "undefined" ? window : globalThis);
