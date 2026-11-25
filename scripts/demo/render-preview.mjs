// Render scripts/demo/social-preview.html to docs/assets/social-preview.png (1280x640) with the system Chrome.
// Needs playwright-core (no browser download): PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core node scripts/demo/render-preview.mjs
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_CORE || "playwright-core");
const chrome = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const browser = await chromium.launch({ executablePath: chrome });
const page = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });
await page.goto(pathToFileURL(path.join(here, "social-preview.html")).href);
await page.evaluate(() => document.fonts.ready);
await page.screenshot({ path: path.join(here, "..", "..", "docs", "assets", "social-preview.png") });
await browser.close();
