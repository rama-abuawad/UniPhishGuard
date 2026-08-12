const fs = require("node:fs");
const path = require("node:path");

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : "";
}

function httpsOrigin(value, name) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be a valid URL.`); }
  if (parsed.protocol !== "https:") throw new Error(`${name} must use HTTPS.`);
  return parsed.origin + parsed.pathname.replace(/\/$/, "");
}

const appUrl = httpsOrigin(argument("--app-url"), "--app-url");
const apiUrl = httpsOrigin(argument("--api-url") || appUrl, "--api-url");
const root = __dirname;
const output = path.join(root, "dist");
fs.mkdirSync(output, { recursive: true });

const manifest = fs.readFileSync(path.join(root, "manifest.xml"), "utf8")
  .replaceAll("https://localhost:8000", appUrl)
  .replace("<AppDomain>https://localhost:3000</AppDomain>", `<AppDomain>${apiUrl}</AppDomain>`);
fs.writeFileSync(path.join(output, "manifest.xml"), manifest);
fs.writeFileSync(path.join(output, "config.js"), `window.UNIPHISHGUARD_API_BASE_URL = ${JSON.stringify(apiUrl)};\n`);
console.log(`Created ${path.join("dist", "manifest.xml")} and ${path.join("dist", "config.js")}`);
