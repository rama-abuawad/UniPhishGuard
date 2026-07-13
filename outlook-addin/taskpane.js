const params = new URLSearchParams(window.location.search);
const API_BASE_URLS = params.get("api")
  ? [params.get("api").replace(/\/analyze-email\/?$/, "")]
  : ["https://localhost:8000"];

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
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(email),
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
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
    const response = await fetch(`${apiBaseUrl}/history`);

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
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
  const headers = await getInternetHeaders(item);
  const sender = item.from || item.sender || {};

  return {
    subject: item.subject || "",
    sender: {
      name: sender.displayName || "",
      email: sender.emailAddress || "unknown@example.com",
    },
    reply_to: getReplyTo(item),
    body,
    headers,
    attachments: (item.attachments || []).map((attachment) => ({
      name: attachment.name,
      content_type: attachment.contentType || null,
      size: attachment.size || null,
    })),
  };
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
    if (!item.getAllInternetHeadersAsync) {
      resolve("");
      return;
    }

    item.getAllInternetHeadersAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        resolve("");
      }
    });
  });
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
  const verdictClass = verdictClassName(report.verdict);
  const confidencePercent = Math.round(report.ai_confidence * 100);
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
          <h2>${escapeHtml(report.verdict)}</h2>
          <p class="meta">Scan #${escapeHtml(report.scan_id || "-")} ${escapeHtml(report.scanned_at || "")}</p>
          <p class="meta">AI phishing detection: ${formatPrediction(report.ai_prediction)} - ${confidencePercent}% AI confidence</p>
        </div>
        <div class="score">${report.risk_score}</div>
      </div>

      <div class="meter-block">
        <div class="meter-row">
          <span>Risk score</span>
          <strong>${report.risk_score}/100</strong>
        </div>
        <div class="meter">
          <span class="meter-fill risk-fill" style="width: ${clampPercent(report.risk_score)}%"></span>
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

      <p class="section-title">Why This Result?</p>
      <ul class="list">${indicators}</ul>

      <p class="section-title">What Should You Do?</p>
      <ul class="list">${actions}</ul>

      <button class="report-button" type="button" onclick="prepareItReport()">Report to IT</button>
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

function renderError(error) {
  lastReport = null;
  resultEl.innerHTML = `
    <div class="error">
      <strong>Scan failed.</strong><br>
      ${escapeHtml(error.message || "Check that the FastAPI backend is running over HTTPS.")}
    </div>
  `;
}

function prepareItReport() {
  if (!lastReport) {
    return;
  }

  const existingReport = document.getElementById("itReport");
  if (existingReport) {
    existingReport.remove();
  }

  const indicatorLines = lastReport.indicators.length
    ? lastReport.indicators
        .map((indicator) => `- ${escapeHtml(indicator.severity.toUpperCase())}: ${escapeHtml(indicator.message)}`)
        .join("<br>")
    : "- No major indicators found";

  resultEl.insertAdjacentHTML("beforeend", `
    <div id="itReport" class="it-report">
      <p class="section-title">IT Report Prepared</p>
      <p class="meta">Use this summary when reporting the email to university IT.</p>
      <div class="report-summary">
        <strong>Verdict:</strong> ${escapeHtml(lastReport.verdict)}<br>
        <strong>Risk score:</strong> ${lastReport.risk_score}/100<br>
        <strong>AI confidence:</strong> ${Math.round(lastReport.ai_confidence * 100)}%<br>
        <strong>Indicators:</strong><br>${indicatorLines}
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
    subject: "Urgent password verification required",
    sender: { name: "IT Support", email: "it@university.edu" },
    reply_to: "support@example.net",
    body: "Click http://192.168.1.10/login to verify your account.",
    headers: "Authentication-Results: spf=pass dkim=pass dmarc=fail",
    attachments: [{ name: "invoice.pdf.exe", content_type: "application/octet-stream", size: 42100 }],
  };
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

function clampPercent(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}
