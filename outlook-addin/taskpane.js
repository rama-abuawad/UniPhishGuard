const params = new URLSearchParams(window.location.search);
const configuredApi = window.UNIPHISHGUARD_API_BASE_URL || "https://localhost:8000";
const devApi = window.UNIPHISHGUARD_ALLOW_API_OVERRIDE && params.get("api")
  ? params.get("api").replace(/\/analyze-email\/?$/, "")
  : null;
const fallbackApis = window.UNIPHISHGUARD_API_FALLBACK_URLS || [];
const API_BASE_URLS = [devApi || configuredApi, ...fallbackApis].filter(Boolean);
const API_TOKEN = window.UNIPHISHGUARD_API_TOKEN || "";
const helpers = window.UniPhishGuardHelpers;

const scanButton = document.getElementById("scanButton");
const historyButton = document.getElementById("historyButton");
const resultEl = document.getElementById("result");
const statusEl = document.getElementById("connectionStatus");
const runtimeNoteEl = document.getElementById("runtimeNote");
let lastReport = null;

if (window.Office) {
  Office.onReady(() => {
    scanButton.addEventListener("click", scanCurrentEmail);
    historyButton.addEventListener("click", loadHistory);
  });
} else {
  runtimeNoteEl.hidden = false;
  runtimeNoteEl.textContent = "Browser preview uses sample email data. Use Outlook to scan a real email.";
  scanButton.addEventListener("click", scanCurrentEmail);
  historyButton.addEventListener("click", loadHistory);
}

async function scanCurrentEmail() {
  setLoading(true);

  try {
    const apiBaseUrl = await findBackend();
    const email = await getCurrentEmail();
    const response = await fetch(`${apiBaseUrl}/analyze-email`, {
      method: "POST",
      headers: await apiHeaders(),
      body: JSON.stringify(email),
    });

    if (!response.ok) {
      throw makeHttpError(response.status);
    }

    renderReport(await response.json());
    statusEl.textContent = "Complete";
  } catch (error) {
    renderError(error);
    statusEl.textContent = "Error";
  } finally {
    setLoading(false);
  }
}

async function loadHistory() {
  setLoading(true);

  try {
    const apiBaseUrl = await findBackend();
    const response = await fetch(`${apiBaseUrl}/history`, {
      headers: await apiHeaders(false),
    });

    if (!response.ok) {
      throw makeHttpError(response.status);
    }

    renderHistory(await response.json());
    statusEl.textContent = "History";
  } catch (error) {
    renderError(error);
    statusEl.textContent = "Error";
  } finally {
    setLoading(false);
  }
}

async function findBackend() {
  const errors = [];

  // Check backend before sending the email data.
  for (const apiBaseUrl of API_BASE_URLS) {
    try {
      const response = await fetch(`${apiBaseUrl}/health`, { method: "GET" });
      if (response.ok) {
        return apiBaseUrl;
      }
      errors.push(`${apiBaseUrl} returned ${response.status}`);
    } catch (error) {
      errors.push(`${apiBaseUrl} could not be reached`);
    }
  }

  throw new Error(`Backend is not reachable. Start it with run_https.cmd and open https://localhost:8000/health. Tried: ${errors.join("; ")}`);
}

async function getCurrentEmail() {
  const item = Office.context?.mailbox?.item;

  if (!item) {
    return sampleEmail();
  }

  const body = await getBodyText(item);
  const bodyHtml = await getBodyHtml(item);
  const headerResult = await getInternetHeaders(item);
  const sender = item.from || item.sender || {};
  const links = extractLinks(bodyHtml, body);

  return {
    subject: item.subject || "",
    sender: {
      name: sender.displayName || "",
      email: sender.emailAddress || "unknown@example.com",
    },
    reply_to: getReplyTo(item),
    body,
    body_html: bodyHtml,
    headers: headerResult.value,
    headers_status: headerResult.status,
    links,
    attachments: (item.attachments || []).map((attachment) => ({
      name: attachment.name,
      content_type: attachment.contentType || null,
      size: attachment.size || null,
    })),
  };
}

function getBodyHtml(item) {
  return new Promise((resolve) => {
    item.body.getAsync(Office.CoercionType.Html, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        resolve("");
      }
    });
  });
}

function getBodyText(item) {
  return new Promise((resolve, reject) => {
    item.body.getAsync(Office.CoercionType.Text, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        reject(new Error(result.error?.message || "Could not read email body"));
      }
    });
  });
}

function getInternetHeaders(item) {
  return new Promise((resolve) => {
    const mailbox = Office.context?.mailbox;
    const supported = Office.context?.requirements?.isSetSupported?.("Mailbox", "1.8");
    if (!supported || !item.getAllInternetHeadersAsync || !mailbox) {
      resolve({ value: "", status: "not_available" });
      return;
    }

    item.getAllInternetHeadersAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve({ value: result.value || "", status: "checked" });
      } else {
        resolve({ value: "", status: "failed" });
      }
    });
  });
}

function extractLinks(html, text) {
  return helpers.extractLinks(html, text);
}

function getReplyTo(item) {
  const replyTo = item.replyTo;

  if (Array.isArray(replyTo) && replyTo.length > 0) {
    return replyTo[0].emailAddress || "";
  }

  return "";
}

function renderReport(report) {
  lastReport = report;
  const threatLevel = normalizeThreatLevel(report);
  const verdictClass = threatLevelClassName(threatLevel.code, report.verdict);
  const threatColor = safeColor(threatLevel.color);
  const confidencePercent = Math.round(report.ai_confidence * 100);
  const categories = renderThreatCategories(report.threat_categories || []);
  const indicators = report.indicators.length
    ? report.indicators.map((indicator) => `
      <li class="${escapeHtml(indicator.severity)}">
        <strong>${escapeHtml(indicator.severity.toUpperCase())}</strong><br>
        ${escapeHtml(indicator.message)}
      </li>
    `).join("")
    : "<li>No major indicators detected.</li>";

  const actions = report.recommended_actions
    .map((action) => `<li>${escapeHtml(action)}</li>`)
    .join("");

  resultEl.innerHTML = `
    <article class="report ${verdictClass}">
      <div class="verdict">
        <div>
          <span class="threat-badge ${escapeHtml(threatLevel.code)}">
            <span class="threat-dot"></span>
            ${escapeHtml(threatLevel.label)}
          </span>
          <h2>${escapeHtml(report.verdict)}</h2>
          <p class="meta">Scan #${escapeHtml(report.scan_id || "-")} ${escapeHtml(report.scanned_at || "")}</p>
          <p class="meta">AI phishing detection: ${formatPrediction(report.ai_prediction)} - ${confidencePercent}% AI confidence</p>
        </div>
        <div class="score">${report.risk_score}</div>
      </div>

      <div class="meter-block">
        <div class="meter-row">
          <span>Threat level</span>
          <strong>${escapeHtml(threatLevel.label)} - ${report.risk_score}/100</strong>
        </div>
        <div class="meter">
          <span class="meter-fill risk-fill" style="width: ${clampPercent(report.risk_score)}%; background: ${threatColor}"></span>
        </div>
      </div>

      <div class="meter-block">
        <div class="meter-row">
          <span>AI confidence</span>
          <strong>${confidencePercent}%</strong>
        </div>
        <div class="meter">
          <span class="meter-fill ai-fill" style="width: ${clampPercent(confidencePercent)}%"></span>
        </div>
      </div>

      <div class="summary-grid">
        <div class="summary-item">
          <span class="summary-label">Links Found</span>
          <span class="summary-value">${report.url_count}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Attachments</span>
          <span class="summary-value">${report.attachment_count}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Risk Indicators</span>
          <span class="summary-value">${report.indicators.length}</span>
        </div>
      </div>

      <p class="section-title">Threat Category</p>
      <div class="category-list">${categories}</div>

      <p class="section-title">Why This Result?</p>
      <ul class="list">${indicators}</ul>

      <p class="section-title">What Should You Do?</p>
      <ul class="list">${actions}</ul>

      <button class="report-button" type="button" onclick="prepareItReport()">Copy IT Report</button>
    </article>
  `;
}

function renderHistory(items) {
  const historyItems = items.length
    ? items.map((item) => `
      <li>
        <p class="history-title">${escapeHtml(item.verdict)} - Risk score ${item.risk_score}/100</p>
        <p class="meta">${escapeHtml(item.subject || "(No subject)")}</p>
        <p class="meta">${escapeHtml(item.sender)} - ${escapeHtml(item.scanned_at)}</p>
      </li>
    `).join("")
    : "<li>No scans saved yet.</li>";

  resultEl.innerHTML = `
    <section>
      <p class="section-title">Recent Scans</p>
      <ul class="history-list">${historyItems}</ul>
    </section>
  `;
}

function renderThreatCategories(categories) {
  if (!categories.length) {
    return '<p class="empty-inline">No specific phishing category detected.</p>';
  }

  return categories.map((category) => `
    <div class="category-chip">
      <strong>${escapeHtml(category.label)}</strong>
      <span>${escapeHtml(helpers.categoryEvidence(category))} evidence</span>
      <small>${escapeHtml(category.reason)}</small>
    </div>
  `).join("");
}

function renderError(error) {
  lastReport = null;
  const detail = classifyError(error);
  resultEl.innerHTML = `
    <div class="error">
      <strong>${escapeHtml(detail.title)}</strong><br>
      ${escapeHtml(detail.message)}
      <p class="meta">Code: ${escapeHtml(detail.code)}</p>
    </div>
  `;
}

async function prepareItReport() {
  if (!lastReport) {
    return;
  }

  const existingReport = document.getElementById("itReport");
  if (existingReport) {
    existingReport.remove();
  }

  const threatLevel = normalizeThreatLevel(lastReport);
  const reportText = helpers.buildReportText({ ...lastReport, threat_level: threatLevel });
  const categoryLines = reportText.split("Threat categories:\n")[1].split("\nIndicators:")[0];
  const indicatorLines = reportText.split("\nIndicators:\n")[1];

  let copied = false;
  try {
    await navigator.clipboard.writeText(reportText);
    copied = true;
  } catch (error) {
    copied = false;
  }

  resultEl.insertAdjacentHTML("beforeend", `
    <div id="itReport" class="it-report">
      <p class="section-title">IT Report ${copied ? "Copied" : "Prepared"}</p>
      <p class="meta">${copied ? "Paste this into the approved ADU IT reporting channel." : "Copy this summary into the approved ADU IT reporting channel."}</p>
      <div class="report-summary">
        <strong>Verdict:</strong> ${escapeHtml(lastReport.verdict)}<br>
        <strong>Threat level:</strong> ${escapeHtml(threatLevel.label)}<br>
        <strong>Risk score:</strong> ${lastReport.risk_score}/100<br>
        <strong>AI confidence:</strong> ${Math.round(lastReport.ai_confidence * 100)}%<br>
        <strong>Threat categories:</strong><br>${escapeHtml(categoryLines).replace(/\n/g, "<br>")}<br>
        <strong>Indicators:</strong><br>${escapeHtml(indicatorLines).replace(/\n/g, "<br>")}
      </div>
    </div>
  `);
}

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  historyButton.disabled = isLoading;
  scanButton.textContent = isLoading ? "Scanning..." : "Scan Email";
  statusEl.textContent = isLoading ? "Scanning" : statusEl.textContent;
}

function sampleEmail() {
  return {
    subject: "ADU IT Helpdesk Microsoft 365 password verification required",
    sender: { name: "ADU IT Helpdesk", email: "support@adu-help.com" },
    reply_to: "support@adu-help.com",
    body: "Click http://192.168.1.10/login or https://aduniversity-login.com/office to verify your Microsoft 365 password.",
    body_html: '<p>Click <a href="https://aduniversity-login.com/office">ADU Portal</a> to verify your Microsoft 365 password.</p>',
    headers: "Authentication-Results: spf=pass dkim=pass dmarc=fail",
    headers_status: "checked",
    links: [{ text: "ADU Portal", href: "https://aduniversity-login.com/office" }],
    attachments: [{ name: "invoice.pdf.exe", content_type: "application/octet-stream", size: 42100 }],
  };
}

async function apiHeaders(includeJson = true) {
  const headers = includeJson ? { "Content-Type": "application/json" } : {};
  const token = API_TOKEN || await getOfficeAccessToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  headers["X-UniPhishGuard-User"] = getMailboxUser();
  return headers;
}

async function getOfficeAccessToken() {
  if (!Office.context?.auth?.getAccessTokenAsync) {
    return "";
  }

  return new Promise((resolve) => {
    Office.context.auth.getAccessTokenAsync({ allowSignInPrompt: true }, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        resolve("");
      }
    });
  });
}

function getMailboxUser() {
  return Office.context?.mailbox?.userProfile?.emailAddress || "local";
}

function makeHttpError(status) {
  const error = new Error(`Backend returned ${status}`);
  error.status = status;
  return error;
}

function classifyError(error) {
  return helpers.classifyError(error);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatPrediction(value) {
  if (value === "phishing") {
    return "Phishing signs found";
  }
  if (value === "legitimate") {
    return "No phishing signs found";
  }
  return escapeHtml(value);
}

function verdictClassName(verdict) {
  const normalized = String(verdict).toLowerCase();
  if (normalized.includes("high-risk")) {
    return "verdict-high";
  }
  if (normalized.includes("phishing")) {
    return "verdict-phishing";
  }
  if (normalized.includes("suspicious")) {
    return "verdict-suspicious";
  }
  return "verdict-legitimate";
}

function normalizeThreatLevel(report) {
  // Fallback for older API responses.
  if (report.threat_level) {
    return report.threat_level;
  }

  const score = Number(report.risk_score) || 0;
  if (score >= 80) {
    return { code: "critical", label: "Critical", color: "#c93232" };
  }
  if (score >= 55) {
    return { code: "high_risk", label: "High Risk", color: "#d45500" };
  }
  if (score >= 25) {
    return { code: "suspicious", label: "Suspicious", color: "#c87816" };
  }
  return { code: "safe", label: "Safe", color: "#1f7a4d" };
}

function threatLevelClassName(code, verdict) {
  if (code === "critical") {
    return "verdict-high";
  }
  if (code === "high_risk") {
    return "verdict-phishing";
  }
  if (code === "suspicious") {
    return "verdict-suspicious";
  }
  if (code === "safe") {
    return "verdict-legitimate";
  }
  return verdictClassName(verdict);
}

function safeColor(value) {
  // Only allow hex colors in inline styles.
  const color = String(value || "");
  if (/^#[0-9a-fA-F]{6}$/.test(color)) {
    return color;
  }
  return "#4477b2";
}

function clampPercent(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}
