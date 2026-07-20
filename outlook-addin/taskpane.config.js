window.UNIPHISHGUARD_API_BASE_URL = window.location.port === "8000"
  ? window.location.origin
  : "https://localhost:8000";
window.UNIPHISHGUARD_API_FALLBACK_URLS = window.location.port === "8000"
  ? []
  : ["https://127.0.0.1:8000"];
window.UNIPHISHGUARD_ALLOW_API_OVERRIDE = false;
window.UNIPHISHGUARD_API_TOKEN = "";
