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
const { buildReportText, categoryEvidence, escapeHtml, normalizeThreatLevel, verdictClassName } = window.UniPhishGuardUtils;

// -----------------------------------------------------------------------------
// UI initialization
// -----------------------------------------------------------------------------

const scanButton = document.getElementById("scanButton");
const historyButton = document.getElementById("historyButton");
const resultEl = document.getElementById("result");
const statusEl = document.getElementById("connectionStatus");
const runtimeNoteEl = document.getElementById("runtimeNote");
let lastReport = null;
let lastScannedEmail = null;
let buttonsBound = false;

bindButtons();

if (window.Office && Office.onReady) {
  Office.onReady(() => {
    bindButtons();
  });
} else {
  bindButtons();
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

    lastScannedEmail = email;
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
  const importantIndicators = (report.indicators || []).filter((indicator) => ["high", "medium"].includes(indicator.severity));
  const checks = buildCheckStatuses(report);
  const reasons = buildResultReasons(report, checks);
  const reasonItems = renderSimpleList(reasons, "No strong phishing evidence was found.");
  const technicalDetails = renderTechnicalDetails(report, importantIndicators);
  const resultSummary = report.risk_score < 25
    ? "No strong phishing evidence was found."
    : report.risk_score < 55
      ? "Some evidence needs verification before you interact with this email."
      : "Multiple strong phishing signals were found.";

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
          <p class="result-summary">${escapeHtml(resultSummary)}</p>
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

      <p class="section-title">Why this result</p>
      <ul class="list">${reasonItems}</ul>

      <p class="section-title">What Should You Do?</p>
      <ul class="list">${actions}</ul>

      ${technicalDetails}

      <button class="report-button" type="button" onclick="openItReportDraft()">Report to IT</button>
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

function renderSimpleList(items, emptyText) {
  return items.length
    ? items.map((item) => `<li class="low">${escapeHtml(item)}</li>`).join("")
    : emptyText ? `<li>${escapeHtml(emptyText)}</li>` : "";
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

function buildCheckStatuses(report) {
  const indicators = report.indicators || [];
  const hasCode = (...prefixes) => indicators.some((indicator) => prefixes.some((prefix) => indicator.code.startsWith(prefix)));
  const hasImportantCode = (...prefixes) => indicators.some((indicator) =>
    ["high", "medium"].includes(indicator.severity) && prefixes.some((prefix) => indicator.code.startsWith(prefix))
  );

  return [
    {
      label: "Sender authentication",
      value: hasImportantCode("spf_", "dkim_", "dmarc_", "auth_") ? "Warning" : hasCode("auth_headers_not_checked", "auth_results_missing") ? "Not available" : "Passed",
      tone: hasImportantCode("spf_", "dkim_", "dmarc_", "auth_") ? "warning" : hasCode("auth_headers_not_checked", "auth_results_missing") ? "neutral" : "safe",
    },
    {
      label: "Links",
      value: hasImportantCode("url_", "link_", "approved_domain") ? "Suspicious" : "Safe",
      tone: hasImportantCode("url_", "link_", "approved_domain") ? "warning" : "safe",
    },
    {
      label: "Attachments",
      value: hasImportantCode("attachment", "double_extension", "dangerous_attachment", "macro_", "archive_", "zip_") ? "Suspicious" : "Safe",
      tone: hasImportantCode("attachment", "double_extension", "dangerous_attachment", "macro_", "archive_", "zip_") ? "warning" : "safe",
    },
    {
      label: "Email wording",
      value: hasCode("ai_phishing_signal") ? "Concerning" : "Normal",
      tone: hasCode("ai_phishing_signal") ? "warning" : "safe",
    },
  ];
}

function buildResultReasons(report, checks) {
  const ruleReasons = (report.top_reasons || []).filter((reason) => !/^AI\b/i.test(reason));
  if (ruleReasons.length) {
    return [...new Set(ruleReasons)].slice(0, 3);
  }

  const reasons = [];
  const authentication = checks.find((check) => check.label === "Sender authentication");
  if (authentication?.value === "Passed") reasons.push("Sender authentication passed.");
  if (checks.find((check) => check.label === "Links")?.value === "Safe") reasons.push("No deceptive or dangerous link pattern was found.");
  if (checks.find((check) => check.label === "Attachments")?.value === "Safe") reasons.push("No dangerous attachment pattern was found.");
  return reasons.slice(0, 3);
}

function renderTechnicalDetails(report, indicators) {
  indicators = indicators.filter((indicator) => indicator.code !== "ai_phishing_signal");
  const categories = report.risk_score >= 25 ? renderThreatCategories(report.threat_categories || []) : "";
  const indicatorItems = indicators.length
    ? `<p class="detail-label">Important indicators</p><ul class="list">${renderSimpleList(indicators.map((indicator) => indicator.message), "")}</ul>`
    : "";
  const categoryItems = categories ? `<p class="detail-label">Detected category</p><div class="category-list">${categories}</div>` : "";
  return `
    <details class="technical-details">
      <summary>Show technical details</summary>
      ${categoryItems}
      ${indicatorItems}
    </details>
  `;
}

function openItReportDraft() {
  if (!lastReport) {
    return;
  }

  const threatLevel = normalizeThreatLevel(lastReport);
  const reportText = buildReportText({ ...lastReport, threat_level: threatLevel });
  const originalDetails = lastScannedEmail
    ? [
        `Original subject: ${lastScannedEmail.subject || "(No subject)"}`,
        `Original sender: ${lastScannedEmail.sender?.name || "Unknown"} <${lastScannedEmail.sender?.email || "unknown"}>`,
      ].join("\n")
    : "";
  const body = [
    "Hello IT Team,",
    "",
    "I would like to report an email for security review. UniPhishGuard produced the following scan summary:",
    "",
    originalDetails,
    reportText,
    "",
    "Please investigate this message.",
  ].join("\n");

  if (!Office.context?.mailbox?.displayNewMessageForm) {
    renderReportActionStatus("Outlook could not open a message draft. Please use Outlook desktop or Outlook on the web.", true);
    return;
  }

  Office.context.mailbox.displayNewMessageForm({
    toRecipients: [],
    subject: `Suspicious email report: ${lastScannedEmail?.subject || "Email for review"}`.slice(0, 255),
    htmlBody: `<pre style="font-family:Segoe UI,Arial,sans-serif;white-space:pre-wrap">${escapeHtml(body)}</pre>`,
  });
  renderReportActionStatus("A report draft was opened. Add your IT recipient, review it, and press Send.");
}

function renderReportActionStatus(message, isError = false) {
  document.getElementById("itReportStatus")?.remove();
  resultEl.insertAdjacentHTML(
    "beforeend",
    `<p id="itReportStatus" class="meta${isError ? " error" : ""}">${escapeHtml(message)}</p>`,
  );
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
    headers: "Authentication-Results: mx.example; spf=pass dkim=pass dmarc=fail",
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
