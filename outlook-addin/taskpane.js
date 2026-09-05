// -----------------------------------------------------------------------------
// Configuration and Office bootstrap
// -----------------------------------------------------------------------------

const params = new URLSearchParams(window.location.search);
const configuredApi = window.UNIPHISHGUARD_API_BASE_URL
  ? String(window.UNIPHISHGUARD_API_BASE_URL).replace(/\/$/, "")
  : window.location.pathname.startsWith("/addin/")
  ? window.location.origin
  : "https://localhost:8000";
const devApi = window.UNIPHISHGUARD_ALLOW_API_OVERRIDE && params.get("api")
  ? params.get("api").replace(/\/analyze-email\/?$/, "")
  : null;
const useSampleEmail = params.get("sample") === "1";
const fallbackApis = window.location.pathname.startsWith("/addin/") ? [] : ["https://127.0.0.1:8000"];
const API_BASE_URLS = [devApi || configuredApi, ...fallbackApis].filter(Boolean);
const API_TOKEN = window.UNIPHISHGUARD_API_TOKEN || "";
const { attachmentCanBeRetrieved, base64Content, buildReportText, categoryEvidence, escapeHtml, inspectionStatuses, normalizeThreatLevel, verdictClassName } = window.UniPhishGuardUtils;
const MAX_ATTACHMENT_BYTES = 5_000_000;
const MAX_TOTAL_ATTACHMENT_BYTES = 5_000_000;

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
    const email = await getCurrentEmail();
    const apiBaseUrl = await findBackend();
    const response = await fetchWithTimeout(`${apiBaseUrl}/api/v1/analyze-email`, {
      method: "POST",
      headers: await apiHeaders(),
      body: JSON.stringify(email),
    }, 90_000);

    if (!response.ok) {
      throw await makeHttpError(response);
    }

    lastScannedEmail = email;
    renderReport(await response.json());
    resultEl.insertAdjacentHTML("afterbegin", `<p class="notice"><strong>Analyzed message:</strong> ${escapeHtml(email.subject || "(No subject)")}<br>From: ${escapeHtml(email.sender.email)}${useSampleEmail && !window.Office?.context?.mailbox ? "<br><strong>DEMO DATA — not your selected email</strong>" : ""}</p>`);
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
    const response = await fetchWithTimeout(`${apiBaseUrl}/api/v1/history`, {
      headers: await apiHeaders(false),
    }, 30_000);

    if (!response.ok) {
      throw await makeHttpError(response);
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
      const response = await fetchWithTimeout(`${apiBaseUrl}/health/ready`, { method: "GET" }, 20_000);
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
  const mailbox = window.Office?.context?.mailbox;

  if (useSampleEmail && !mailbox && !isOutlookHost()) {
    showSampleMode();
    return sampleEmail();
  }

  const item = await waitForCurrentItem();

  if (!item) {
    throw new Error(`Outlook did not expose the selected email to the add-in (${officeDiagnostic()}). Close and reopen this pane.`);
  }

  if (looksLikeEmptyOutlookItem(item)) {
    throw new Error("Outlook did not provide the selected email yet. Re-select it, wait a moment, then scan again.");
  }

  if (!item.body?.getAsync) {
    throw new Error("Outlook did not provide the email body. Re-open the add-in and scan again.");
  }

  const body = await getBodyText(item);
  const bodyHtml = await getBodyHtml(item);
  const headerResult = await getInternetHeaders(item);
  const attachmentResult = await getAttachments(item);
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
    attachment_content_status: attachmentResult.status,
    internet_message_id: item.internetMessageId || null,
    received_at: item.dateTimeCreated ? new Date(item.dateTimeCreated).toISOString() : null,
    links,
    attachments: attachmentResult.attachments,
  };
}

function isOutlookHost() {
  const host = window.uniphishguardOfficeInfo?.host;
  const outlook = window.Office?.HostType?.Outlook || "Outlook";
  return String(host || "").toLowerCase() === String(outlook).toLowerCase()
    || /^outlook\$/i.test(params.get("_host_Info") || "");
}

function showSampleMode() {
  runtimeNoteEl.hidden = false;
  runtimeNoteEl.textContent = "Browser preview: scanning the built-in sample email. No Outlook message was accessed.";
}

async function getAttachments(item) {
  const source = item.attachments || [];
  const attachments = source.map((attachment) => ({
    name: attachment.name,
    content_type: attachment.contentType || null,
    size: attachment.size || null,
  }));
  if (!source.length) return { attachments, status: "checked" };

  const supported = Office.context?.requirements?.isSetSupported?.("Mailbox", "1.8");
  if (!supported || !item.getAttachmentContentAsync) {
    return { attachments, status: "not_available" };
  }

  let retrieved = 0;
  let skipped = 0;
  let retrievedBytes = 0;
  for (let index = 0; index < source.length; index += 1) {
    const attachment = source[index];
    if (!attachmentCanBeRetrieved(attachment, Math.min(MAX_ATTACHMENT_BYTES, MAX_TOTAL_ATTACHMENT_BYTES - retrievedBytes))) {
      skipped += 1;
      continue;
    }
    const content = await getAttachmentContent(item, attachment.id);
    if (content) {
      attachments[index].content_base64 = content;
      retrievedBytes += Math.floor(content.length * 3 / 4);
      retrieved += 1;
    } else {
      skipped += 1;
    }
  }
  return {
    attachments,
    status: retrieved === source.length ? "checked" : retrieved > 0 ? "partial" : skipped ? "not_available" : "failed",
  };
}

function getAttachmentContent(item, attachmentId) {
  return new Promise((resolve) => {
    item.getAttachmentContentAsync(attachmentId, (result) => {
      if (result.status !== Office.AsyncResultStatus.Succeeded) {
        resolve(null);
        return;
      }
      const content = base64Content(result.value);
      if (!content || content.length > Math.ceil(MAX_ATTACHMENT_BYTES * 4 / 3) + 8) {
        resolve(null);
        return;
      }
      resolve(content);
    });
  });
}

async function waitForOfficeHost(timeoutMs = 10000) {
  if (!window.uniphishguardOfficeReady) {
    return;
  }

  let timeout;
  try {
    await Promise.race([
      window.uniphishguardOfficeReady,
      new Promise((resolve) => { timeout = setTimeout(resolve, timeoutMs); }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function officeDiagnostic() {
  const office = Boolean(window.Office);
  const context = Boolean(window.Office?.context);
  const mailbox = Boolean(window.Office?.context?.mailbox);
  const item = Boolean(window.Office?.context?.mailbox?.item);
  const host = window.uniphishguardOfficeInfo?.host || "none";
  return `host=${host}, Office=${office}, context=${context}, mailbox=${mailbox}, item=${item}`;
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
  const technicalDetails = renderTechnicalDetails(report, importantIndicators, checks);
  const incomplete = report.analysis_completeness !== "complete";
  const limitationItems = renderSimpleList(report.analysis_limitations || [], "");
  const resultSummary = threatLevel.code === "low_risk"
    ? incomplete
      ? "No strong phishing evidence was found in the evidence Outlook made available. Some checks were incomplete."
      : "No strong phishing evidence was found in the inspected evidence."
    : threatLevel.code === "suspicious"
      ? "Some evidence needs verification before you interact with this email."
      : "Multiple strong phishing signals were found.";

  const actions = (report.recommended_actions || [])
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
        <div class="score">${escapeHtml(report.risk_score)}</div>
      </div>

      <div class="meter-block">
        <div class="meter-row">
          <span>Risk score</span>
          <strong>${escapeHtml(threatLevel.label)} - ${escapeHtml(report.risk_score)}/100</strong>
        </div>
        <div class="meter">
          <span class="meter-fill risk-fill" style="width: ${clampPercent(report.risk_score)}%; background: ${threatColor}"></span>
        </div>
      </div>

      ${incomplete ? `<div class="notice"><strong>Partial analysis</strong><ul class="list">${limitationItems}</ul></div>` : ""}

      <p class="section-title">Why this result</p>
      <ul class="list">${reasonItems}</ul>

      <p class="section-title">What Should You Do?</p>
      <ul class="list">${actions}</ul>

      ${technicalDetails}

      <button id="reportToItButton" class="report-button" type="button">Report to IT</button>
    </article>
  `;
  document.getElementById("reportToItButton")?.addEventListener("click", openItReportDraft);
}

function renderHistory(items) {
  const historyItems = items.length
    ? items.map((item) => `
      <li>
        <p class="history-title">${escapeHtml(item.verdict)} - Risk score ${escapeHtml(item.risk_score)}/100</p>
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
  return inspectionStatuses(report);
}

function buildResultReasons(report, checks) {
  const ruleReasons = (report.top_reasons || []).filter((reason) => !/^AI\b/i.test(reason));
  if (ruleReasons.length) {
    return [...new Set(ruleReasons)].slice(0, 3);
  }

  const reasons = [];
  const authentication = checks.find((check) => check.label === "Sender authentication");
  if (authentication?.value === "Passed") reasons.push("Sender authentication passed.");
  if (checks.find((check) => check.label === "Links")?.value.startsWith("No suspicious")) reasons.push("No suspicious link pattern was detected.");
  if (checks.find((check) => check.label === "Attachments")?.value.startsWith("No suspicious")) reasons.push("No suspicious attachment pattern was detected.");
  return reasons.slice(0, 3);
}

function renderTechnicalDetails(report, indicators, checks) {
  indicators = indicators.filter((indicator) => indicator.code !== "ai_phishing_signal");
  const headerIndicatorCodes = /^(?:auth_|spf_|dkim_|dmarc_|forwarding_or_arc_context$|reply_to_mismatch$)/;
  const headerIndicators = indicators.filter((indicator) => headerIndicatorCodes.test(indicator.code));
  const otherIndicators = indicators.filter((indicator) => !headerIndicatorCodes.test(indicator.code));
  const attackCategories = report.threat_categories || [];
  const headerItems = headerIndicators.length
    ? `<p class="detail-label">Header and authentication issues</p><ul class="list">${renderSimpleList(headerIndicators.map((indicator) => indicator.message), "")}</ul>`
    : "";
  const indicatorItems = otherIndicators.length
    ? `<p class="detail-label">Other important findings</p><ul class="list">${renderSimpleList(otherIndicators.map((indicator) => indicator.message), "")}</ul>`
    : "";
  const categoryItems = attackCategories.length
    ? `<p class="detail-label">Possible attack types</p><div class="category-list">${renderThreatCategories(attackCategories)}</div>`
    : "";
  const components = Object.fromEntries((report.score_breakdown || []).map((item) => [item.code, item.score]));
  const qrLinks = (report.decoded_qr_links || []).map((item) => item.href);
  const headerStatus = {
    checked: "Available and checked",
    not_available: "Not available in Outlook",
    failed: "Could not be retrieved",
  }[report.authentication_headers_status] || "Not available";
  const detailRows = [
    ["Risk score", `${report.risk_score}/100`],
    ["Analysis completeness", report.analysis_completeness || "partial"],
    ["Verdict", report.verdict],
    ["Threat level", report.threat_level?.label || "Unknown"],
    ["ML phishing probability", `${Math.round((report.ai_confidence || 0) * 100)}%`],
    ["ML risk impact", `${components.ai_language || 0}`],
    ["Authentication risk impact", `${components.authentication || 0}`],
    ["Sender/rule risk impact", `${components.sender_identity || 0}`],
    ["URL risk impact", `${components.urls || 0}`],
    ["Attachment risk impact", `${components.attachments || 0}`],
    ["Impersonation risk impact", `${components.university_impersonation || 0}`],
    ["URLs inspected", `${report.url_count || 0}`],
    ["Attachments listed", `${report.attachment_count || 0}`],
    ["Attachment contents inspected", `${report.attachment_contents_inspected || 0} (${report.attachment_content_status || "unavailable"})`],
    ["Email headers", headerStatus],
    ["QR URLs discovered", qrLinks.length ? qrLinks.join(", ") : "None"],
  ].map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join("");
  const checkRows = checks.map((check) => `<dt>${escapeHtml(check.label)}</dt><dd class="${escapeHtml(check.tone)}">${escapeHtml(check.value)}</dd>`).join("");
  return `
    <details class="technical-details">
      <summary>Show technical details</summary>
      <p class="detail-label">Inspection status</p>
      <dl class="technical-grid">${checkRows}</dl>
      <dl class="technical-grid">${detailRows}</dl>
      ${categoryItems}
      ${headerItems}
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
        `Scan ID: ${lastReport.scan_id || "Unavailable"}`,
        `Internet Message ID: ${lastScannedEmail.internet_message_id || "Unavailable"}`,
        `Original subject: ${lastScannedEmail.subject || "(No subject)"}`,
        `Original sender: ${lastScannedEmail.sender?.name || "Unknown"} <${lastScannedEmail.sender?.email || "unknown"}>`,
        `Message timestamp: ${lastScannedEmail.received_at || "Unavailable"}`,
        `URLs inspected: ${lastReport.url_count || 0}`,
        `Attachments listed: ${lastReport.attachment_count || 0}`,
        `Attachment contents inspected: ${lastReport.attachment_contents_inspected || 0}`,
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
    headers: "Authentication-Results: spf.protection.outlook.com; spf=pass dkim=pass dmarc=fail",
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
  const auth = window.Office?.auth || window.Office?.context?.auth;
  if (!auth) {
    return "";
  }

  if (typeof auth.getAccessToken === "function") {
    try {
      return await auth.getAccessToken({ allowSignInPrompt: true, allowConsentPrompt: true });
    } catch {
      // Older Outlook clients may only expose the callback API below.
    }
  }

  if (typeof auth.getAccessTokenAsync !== "function") {
    return "";
  }

  return new Promise((resolve) => {
    auth.getAccessTokenAsync({ allowSignInPrompt: true, allowConsentPrompt: true }, (result) => {
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

async function makeHttpError(response) {
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  const detail = payload?.message || payload?.detail?.message || (typeof payload?.detail === "string" ? payload.detail : "");
  const requestId = response.headers?.get?.("X-Request-ID") || payload?.request_id || "";
  const suffix = [detail, requestId ? `Request ID: ${requestId}` : ""].filter(Boolean).join(" ");
  const error = new Error(suffix || `Backend returned ${response.status}`);
  error.status = response.status;
  return error;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 30_000) {
  if (typeof AbortController === "undefined") {
    return fetch(url, options);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
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
  if (/timed out/i.test(error.message || "")) {
    return { title: "Backend timeout.", message: error.message, code: "BACKEND_TIMEOUT" };
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
  if (code === "safe" || code === "low_risk") {
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
