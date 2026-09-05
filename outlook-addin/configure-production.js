const fs = require("node:fs");
const path = require("node:path");

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : "";
}

function setting(argumentName, environmentName) {
  return argument(argumentName) || process.env[environmentName] || "";
}

function httpsOrigin(value, name) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be a valid URL.`); }
  if (parsed.protocol !== "https:") throw new Error(`${name} must use HTTPS.`);
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !["", "/"].includes(parsed.pathname)) {
    throw new Error(`${name} must be an HTTPS origin without credentials, a path, query, or fragment.`);
  }
  const hostname = parsed.hostname.toLowerCase();
  const reserved = ["example.com", "example.net", "example.org", "localhost"].includes(hostname)
    || [".example", ".example.com", ".example.net", ".example.org", ".invalid", ".localhost", ".test"]
      .some((suffix) => hostname.endsWith(suffix));
  if (reserved) throw new Error(`${name} must use a real production hostname.`);
  return parsed.origin;
}

const appUrl = httpsOrigin(setting("--app-url", "UNIPHISHGUARD_APP_URL"), "--app-url/UNIPHISHGUARD_APP_URL");
const apiUrl = httpsOrigin(setting("--api-url", "UNIPHISHGUARD_API_URL") || appUrl, "--api-url/UNIPHISHGUARD_API_URL");
const clientId = setting("--client-id", "ENTRA_CLIENT_ID");
if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(clientId)) {
  throw new Error("--client-id must be the Microsoft Entra application client ID.");
}
const resource = setting("--resource", "ENTRA_RESOURCE") || `api://${new URL(appUrl).host}/${clientId}`;
if (!/^(?:api|https):\/\/[^\s<>&"']+$/i.test(resource)) {
  throw new Error("--resource must be a valid HTTPS or api application ID URI.");
}
const root = __dirname;
const output = path.join(root, "dist");
const addinOutput = path.join(output, "addin");
fs.mkdirSync(output, { recursive: true });
fs.mkdirSync(addinOutput, { recursive: true });

for (const file of ["taskpane.html", "taskpane.css", "taskpane.js", "taskpane-utils.js", "office-bootstrap.js"]) {
  fs.copyFileSync(path.join(root, file), path.join(addinOutput, file));
}
fs.cpSync(path.join(root, "assets"), path.join(addinOutput, "assets"), { recursive: true });

const configuredManifest = fs.readFileSync(path.join(root, "manifest.xml"), "utf8")
  .replaceAll("https://localhost:8000", appUrl)
  .replace("<AppDomain>https://localhost:3000</AppDomain>", `<AppDomain>${apiUrl}</AppDomain>`);
const overrides = configuredManifest.match(
  /<VersionOverrides xmlns="http:\/\/schemas\.microsoft\.com\/office\/mailappversionoverrides"\s+xsi:type="VersionOverridesV1_0">([\s\S]*?)<\/VersionOverrides>/,
);
if (!overrides) throw new Error("The source manifest does not contain the expected Outlook VersionOverridesV1_0 section.");
const webApplicationInfo = `    <WebApplicationInfo>\n      <Id>${clientId}</Id>\n      <Resource>${resource}</Resource>\n      <Scopes>\n        <Scope>openid</Scope>\n        <Scope>profile</Scope>\n        <Scope>email</Scope>\n      </Scopes>\n    </WebApplicationInfo>`;
const v11 = `    <VersionOverrides xmlns="http://schemas.microsoft.com/office/mailappversionoverrides/1.1" xsi:type="VersionOverridesV1_1">${overrides[1]}\n${webApplicationInfo}\n    </VersionOverrides>`;
const manifest = configuredManifest.replace(
  overrides[0],
  `${overrides[0].slice(0, -"</VersionOverrides>".length)}\n${v11}\n  </VersionOverrides>`,
);
fs.writeFileSync(path.join(output, "manifest.xml"), manifest);
fs.writeFileSync(path.join(addinOutput, "config.js"), `window.UNIPHISHGUARD_API_BASE_URL = ${JSON.stringify(apiUrl)};\n`);
console.log(`Created ${path.join("dist", "manifest.xml")} and the deployable ${path.join("dist", "addin")} site.`);
