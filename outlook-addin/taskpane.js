// -----------------------------------------------------------------------------
// Configuration and Office bootstrap
// -----------------------------------------------------------------------------

const params = new URLSearchParams(window.location.search);
const configuredApi = window.location.port === "8000"
  ? window.location.origin
  : "https://localhost:8000";
const devApi = window.UNIPHISHGUARD_ALLOW_API_OVERRIDE && params.get("api")
  ? params.get("api").replace(/\/analyze-email\/?$/, "")
  : null;
const useSampleEmail = params.get("sample") === "1";
const fallbackApis = window.location.port === "8000" ? [] : ["https://127.0.0.1:8000"];
const API_BASE_URLS = [devApi || configuredApi, ...fallbackApis].filter(Boolean);
const API_TOKEN = window.UNIPHISHGUARD_API_TOKEN || "";

let finishOfficeReady;
let officeReadyFinished = false;
window.uniphishguardOfficeReady = new Promise((resolve) => {
  finishOfficeReady = (info) => {
    if (!officeReadyFinished) {
      officeReadyFinished = true;
      resolve(info || {});
    }
  };
});

if (!window.Office) {
  finishOfficeReady({ host: "browser" });
} else {
  Office.initialize = () => finishOfficeReady({ host: "outlook", source: "initialize" });
  if (typeof Office.onReady === "function") {
    Office.onReady((info) => finishOfficeReady(info)).catch(() => {});
  }
}

// -----------------------------------------------------------------------------
// UI initialization
// -----------------------------------------------------------------------------

const scanButton = document.getElementById("scanButton");
const historyButton = document.getElementById("historyButton");
const resultEl = document.getElementById("result");
const statusEl = document.getElementById("connectionStatus");
const runtimeNoteEl = document.getElementById("runtimeNote");
let lastReport = null;
let buttonsBound = false;

bindButtons();

if (window.Office && Office.onReady) {
  Office.onReady(() => {
    bindButtons();
  });
} else {
  runtimeNoteEl.hidden = false;
  runtimeNoteEl.textContent = useSampleEmail
    ? "Browser preview is using sample email data."
    : "Use Outlook to scan a real email.";
}

function bindButtons() {
  if (buttonsBound) {
    return;
  }
  if (scanButton && historyButton) {
    scanButton.addEventListener("click", scanCurrentEmail);
    historyButton.addEventListener("click", loadHistory);
    buttonsBound = true;
  }
}

// -----------------------------------------------------------------------------
// Backend API
// -----------------------------------------------------------------------------

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

  throw new Error(`Backend is not reachable. Start FastAPI and open https://localhost:8000/health. Tried: ${errors.join("; ")}`);
}

// -----------------------------------------------------------------------------
// Outlook message collection
// -----------------------------------------------------------------------------

async function getCurrentEmail() {
  await waitForOfficeHost();
  const item = await waitForCurrentItem();
  const mailbox = window.Office?.context?.mailbox;

  if (!item) {
    if (useSampleEmail && (!window.Office || !mailbox)) {
      return sampleEmail();
    }

    throw new Error(`Outlook did not expose the selected email to the add-in (${officeDiagnostic()}). Close and reopen this pane.`);
  }

  if (looksLikeEmptyOutlookItem(item)) {
    throw new Error("Outlook did not provide the selected email yet. Re-select it, wait a moment, then scan again.");
  }

  if (!item.body?.getAsync) {
    if (useSampleEmail && (!window.Office || !mailbox)) {
      return sampleEmail();
    }

    throw new Error("Outlook did not provide the email body. Re-open the add-in and scan again.");
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

async function waitForOfficeHost(timeoutMs = 10000) {
  if (!window.uniphishguardOfficeReady) {
    return;
  }

  await Promise.race([
    window.uniphishguardOfficeReady,
    new Promise((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
}

function officeDiagnostic() {
  const office = Boolean(window.Office);
  const context = Boolean(window.Office?.context);
  const mailbox = Boolean(window.Office?.context?.mailbox);
  const item = Boolean(window.Office?.context?.mailbox?.item);
  return `Office=${office}, context=${context}, mailbox=${mailbox}, item=${item}`;
}

async function waitForCurrentItem(timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const item = window.Office?.context?.mailbox?.item;
    if (item) {
      return item;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  return null;
}

function looksLikeEmptyOutlookItem(item) {
  return !item.subject && !item.from && !item.sender && !item.body;
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
  const links = [];
  if (html && window.DOMParser) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    doc.querySelectorAll("a[href]").forEach((anchor) => {
      links.push({
        text: (anchor.textContent || "").trim().slice(0, 500),
        href: anchor.href || anchor.getAttribute("href"),
      });
    });
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

function getReplyTo(item) {
  const replyTo = item.replyTo;

  if (Array.isArray(replyTo) && replyTo.length > 0) {
    return replyTo[0].emailAddress || "";
  }

  return "";
}

// -----------------------------------------------------------------------------
// Report and history rendering
// -----------------------------------------------------------------------------

function renderReport(report) {
  lastReport = report;
  const threatLevel = normalizeThreatLevel(report);
  const verdictClass = threatLevelClassName(threatLevel.code, report.verdict);
  const threatColor = safeColor(threatLevel.color);
  const confidencePercent = Math.round(report.ai_confidence * 100);
  const reputationStatus = report.url_reputation_status === "checked"
    ? `${report.url_reputation_checked || 0} URL(s) checked externally`
    : report.url_reputation_status === "unavailable"
      ? "external service unavailable"
      : "not configured";
  const categories = renderThreatCategories(report.threat_categories || []);
  const breakdown = renderScoreBreakdown(report.score_breakdown || []);
  const topReasons = renderSimpleList(report.top_reasons || [], "No strong reason found.");
  const aiEvidence = renderSimpleList(report.ai_evidence || [], "No specific suspicious language found.");
  const attachmentHashes = renderSimpleList(report.attachment_hashes || [], "No attachment content hash available.");
  const qrLinks = renderQrLinks(report.decoded_qr_links || []);
  const groupedIndicators = renderIndicatorSections(report.indicators || []);

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
          <p class="meta">AI language check: ${formatPrediction(report.ai_prediction)} - ${confidencePercent}% phishing probability</p>
          <p class="meta">URL reputation: ${escapeHtml(reputationStatus)}</p>
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
          <span>AI phishing probability</span>
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

      <p class="section-title">Score Breakdown</p>
      <div class="breakdown-list">${breakdown}</div>

      <p class="section-title">Strongest Reasons</p>
      <ul class="list">${topReasons}</ul>

      <p class="section-title">AI Language Assessment</p>
      <ul class="list">${aiEvidence}</ul>

      <p class="section-title">Attachment Hashes</p>
      <ul class="list">${attachmentHashes}</ul>

      <p class="section-title">Decoded QR Links</p>
      <ul class="list">${qrLinks}</ul>

      ${groupedIndicators}

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
      <span>${escapeHtml(categoryEvidence(category))} evidence</span>
      <small>${escapeHtml(category.reason)}</small>
    </div>
  `).join("");
}

function renderScoreBreakdown(items) {
  if (!items.length) {
    return '<p class="empty-inline">No score components added.</p>';
  }

  return items.map((item) => `
    <div class="breakdown-item">
      <span>${escapeHtml(item.label)}</span>
      <strong>${escapeHtml(item.score)}/${escapeHtml(item.cap)}</strong>
    </div>
  `).join("");
}

function renderSimpleList(items, emptyText) {
  return items.length
    ? items.map((item) => `<li class="low">${escapeHtml(item)}</li>`).join("")
    : `<li>${escapeHtml(emptyText)}</li>`;
}

function renderQrLinks(links) {
  return links.length
    ? links.map((link) => `<li class="medium">${escapeHtml(link.href)}</li>`).join("")
    : "<li>No QR link found.</li>";
}

function renderIndicatorSections(indicators) {
  const groups = [
    ["Sender Authentication", ["spf_", "dkim_", "dmarc_", "auth_", "forwarding_"]],
    ["URL Analysis", ["url_", "link_", "approved_domain", "external_sender"]],
    ["Attachment Analysis", ["attachment", "double_extension", "dangerous_attachment", "macro_", "archive_"]],
    ["Sender and University Checks", ["reply_to", "university_", "untrusted_", "fake_university"]],
  ];

  const used = new Set();
  const sections = groups.map(([title, prefixes]) => {
    const matches = indicators.filter((indicator) => {
      const matched = prefixes.some((prefix) => indicator.code.startsWith(prefix));
      if (matched) {
        used.add(indicator);
      }
      return matched;
    });
    return renderIndicatorSection(title, matches);
  });

  const other = indicators.filter((indicator) => !used.has(indicator));
  sections.push(renderIndicatorSection("Other Evidence", other));
  return sections.join("");
}

function renderIndicatorSection(title, indicators) {
  const body = indicators.length
    ? indicators.map((indicator) => `
      <li class="${escapeHtml(indicator.severity)}">
        <strong>${escapeHtml(indicator.severity.toUpperCase())}</strong><br>
        ${escapeHtml(indicator.message)}
      </li>
    `).join("")
    : "<li>No issue found in this section.</li>";

  return `
    <p class="section-title">${escapeHtml(title)}</p>
    <ul class="list">${body}</ul>
  `;
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
  const reportText = buildReportText({ ...lastReport, threat_level: threatLevel });
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

// -----------------------------------------------------------------------------
// Authentication, errors, and shared utilities
// -----------------------------------------------------------------------------

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
  if (error.status === 401 || error.status === 403) {
    return { title: "Authentication needed.", message: "Sign in or check the configured API token before scanning again.", code: `AUTH_${error.status}` };
  }
  if (error.status === 413 || error.status === 422) {
    return { title: "Email is too large to scan.", message: "Try a smaller message or remove very large metadata before scanning.", code: `INPUT_${error.status}` };
  }
  if (error.status === 429) {
    return { title: "Too many scans.", message: "Wait a minute and try again.", code: "RATE_LIMIT" };
  }
  if (/certificate|ssl|tls/i.test(error.message || "")) {
    return { title: "Certificate problem.", message: "Open the backend health URL and accept the local certificate, then scan again.", code: "CERTIFICATE" };
  }
  if (/not reachable|failed to fetch|network/i.test(error.message || "")) {
    return { title: "Backend offline.", message: `Start the backend and check https://localhost:8000/health. ${error.message || ""}`.trim(), code: "BACKEND_OFFLINE" };
  }
  return { title: "Scan failed.", message: error.message || "Check that the FastAPI backend is running over HTTPS.", code: "SCAN_ERROR" };
}

function categoryEvidence(category) {
  return category.evidence_strength || category.confidence || "medium";
}

function buildReportText(report) {
  const threatLevel = report.threat_level || { label: "Unknown" };
  const categories = (report.threat_categories || []).length
    ? report.threat_categories.map((category) => `- ${category.label} (${categoryEvidence(category)} evidence)`).join("\n")
    : "- No specific category detected";
  const indicators = (report.indicators || []).length
    ? report.indicators.map((indicator) => `- ${String(indicator.severity || "").toUpperCase()}: ${indicator.message}`).join("\n")
    : "- No major indicators found";
  const breakdown = (report.score_breakdown || []).length
    ? report.score_breakdown.map((item) => `- ${item.label}: ${item.score}/${item.cap}`).join("\n")
    : "- No score components added";
  const aiEvidence = (report.ai_evidence || []).length
    ? report.ai_evidence.map((phrase) => `- ${phrase}`).join("\n")
    : "- No specific suspicious language found";
  const hashes = (report.attachment_hashes || []).length
    ? report.attachment_hashes.map((value) => `- ${value}`).join("\n")
    : "- No attachment content hash available";
  const qrLinks = (report.decoded_qr_links || []).length
    ? report.decoded_qr_links.map((link) => `- ${link.href}`).join("\n")
    : "- No QR link found";

  return [
    "UniPhishGuard report",
    `Verdict: ${report.verdict}`,
    `Threat level: ${threatLevel.label}`,
    `Risk score: ${report.risk_score}/100`,
    `AI phishing probability: ${Math.round((report.ai_confidence || 0) * 100)}%`,
    `URL reputation: ${report.url_reputation_status || "not_configured"} (${report.url_reputation_checked || 0} checked)`,
    "Score breakdown:", breakdown,
    "AI language evidence:", aiEvidence,
    "Attachment hashes:", hashes,
    "Decoded QR links:", qrLinks,
    "Threat categories:", categories,
    "Indicators:", indicators,
  ].join("\n");
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
