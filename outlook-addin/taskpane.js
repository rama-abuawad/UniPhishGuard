const params = new URLSearchParams(window.location.search);
const API_BASE_URLS = params.get("api")
  ? [params.get("api").replace(/\/analyze-email\/?$/, "")]
  : ["https://localhost:8000"];

const scanButton = document.getElementById("scanButton");
const resultEl = document.getElementById("result");
const statusEl = document.getElementById("connectionStatus");
const runtimeNoteEl = document.getElementById("runtimeNote");

if (window.Office) {
  Office.onReady(() => {
    scanButton.addEventListener("click", scanCurrentEmail);
  });
} else {
  runtimeNoteEl.hidden = false;
  runtimeNoteEl.textContent = "Browser preview mode uses sample email data. Sideload in Outlook to scan the opened message.";
  scanButton.addEventListener("click", scanCurrentEmail);
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

async function findBackend() {
  const errors = [];

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

  throw new Error(`Backend is not reachable. Start backend with .\\run_https.ps1, then open https://localhost:8000/health once in Edge. Tried: ${errors.join("; ")}`);
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
    <article class="report">
      <div class="verdict">
        <div>
          <h2>${escapeHtml(report.verdict)}</h2>
          <p class="meta">AI: ${escapeHtml(report.ai_prediction)} (${Math.round(report.ai_confidence * 100)}% confidence)</p>
        </div>
        <div class="score">${report.risk_score}</div>
      </div>

      <p class="section-title">Detected Indicators</p>
      <ul class="list">${indicators}</ul>

      <p class="section-title">Recommended Actions</p>
      <ul class="list">${actions}</ul>
    </article>
  `;
}

function renderError(error) {
  resultEl.innerHTML = `
    <div class="error">
      <strong>Scan failed.</strong><br>
      ${escapeHtml(error.message || "Check that the FastAPI backend is running over HTTPS.")}
    </div>
  `;
}

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
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
