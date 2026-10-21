// SPDX-License-Identifier: Apache-2.0
// Browser smoke test of the interactive maps (driven by tests/browser/test_maps_browser.py):
// loads the static topology.html and dataflow.html in headless Chromium through Playwright,
// exercises them, and prints one JSON object of observations for the Python test to judge.
// Usage: node map_smoke.mjs <topology.html> <dataflow.html> <hostile node id> [screenshot dir]
import { createRequire } from "module";

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch (err) {
  console.log(JSON.stringify({ skip: "playwright for node not installed" }));
  process.exit(0);
}

const [, , topoPath, dfPath, hostileNode, shots] = process.argv;
let browser;
try {
  browser = await chromium.launch();
} catch (err) {
  console.log(JSON.stringify({ skip: "chromium not installed: " + String(err.message).split("\n")[0] }));
  process.exit(0);
}

async function open(path, theme) {
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, colorScheme: theme });
  const errors = [];
  page.on("console", (m) => {
    if (m.type() === "error") errors.push("console: " + m.text());
  });
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(e.violatedDirective));
  });
  await page.goto("file://" + path);
  await page.waitForTimeout(150);
  return { page, errors };
}

const out = {};
// ── topology ──
{
  const { page, errors } = await open(topoPath, "dark");
  const t = {};
  t.cards = await page.locator(".net-card").count();
  t.arrowsBefore = await page.locator("#flow-svg path.flow-arrow").count();
  if (shots) await page.screenshot({ path: shots + "/topology.png" });
  await page.click("#flow-toggle");
  t.arrowsOn = await page.locator("#flow-svg path.flow-arrow").count();
  t.plannedArrows = await page.locator("#flow-svg path.flow-arrow.planned").count();
  t.toggleText = await page.textContent("#flow-toggle");
  await page.locator('.net-card[data-node="guest:siem-1"]').click();
  await page.waitForTimeout(250);
  t.panelOpen = await page.locator("#detail-panel.open").count();
  t.panelTitle = await page.textContent("#detail-content h3");
  t.panelText = await page.textContent("#detail-content");
  t.flowItems = await page.locator("#detail-content .flow-item").count();
  t.highlighted = await page.locator("#flow-svg path.flow-arrow.highlighted").count();
  t.flowDimmed = await page.locator(".net-card.flow-dimmed").count();
  t.tooltip = await page.textContent("#tooltip-el");
  if (shots) await page.screenshot({ path: shots + "/topology-flows.png" });
  // the hostile guest: its text must arrive as text, nothing executes
  await page.click("#detail-close");
  await page.locator(`.net-card[data-node="${hostileNode}"]`).click();
  await page.waitForTimeout(100);
  t.hostileText = await page.textContent("#detail-content");
  t.hostileImgs = await page.locator("#detail-content img, #tooltip-el img").count();
  t.pwned = await page.evaluate(() => window.__pwned === undefined ? null : window.__pwned);
  await page.click("#detail-close");
  t.panelClosed = (await page.locator("#detail-panel.open").count()) === 0;
  await page.locator(`.net-card[data-node="${hostileNode}"]`).hover();
  t.hostileTip = await page.textContent("#tooltip-el");
  // power: UPS lines on the toggle, the no-UPS bench machine's badge, tooltip and detail
  await page.click("#power-toggle");
  t.powerLines = await page.locator("#flow-svg path.power-line").count();
  t.powerToggle = await page.textContent("#power-toggle");
  await page.locator('.net-card[data-node="guest:bench-1"]').hover();
  t.benchTip = await page.textContent("#tooltip-el");
  await page.locator('.net-card[data-node="guest:bench-1"]').click();
  t.benchPanel = await page.textContent("#detail-content");
  await page.click("#detail-close");
  await page.locator('.net-card[data-node="guest:siem-1"]').click();
  t.siemPower = await page.textContent("#detail-content .power-item");
  await page.click("#detail-close");
  await page.click("#power-toggle");
  t.powerLinesOff = await page.locator("#flow-svg path.power-line").count();
  // filter, Esc clears; Ctrl+F focuses the box
  await page.keyboard.press("Control+f");
  t.focused = await page.evaluate(() => document.activeElement && document.activeElement.id);
  await page.keyboard.type("bus-1");
  t.filterHits = await page.locator(".net-card.highlight").count();
  t.filterDimmed = await page.locator(".net-card.dimmed").count();
  await page.keyboard.press("Escape");
  t.afterEsc = await page.locator(".net-card.highlight, .net-card.dimmed").count();
  // collapse a lane
  await page.locator(".vlan-header").first().click();
  t.laneCollapsed = await page.locator(".vlan-content.collapsed").count();
  t.laneExpanded = await page.locator(".vlan-header").first().getAttribute("aria-expanded");
  // zoom, reset, theme
  const before = await page.evaluate(() => document.getElementById("topo-inner").style.transform);
  await page.mouse.move(900, 600);
  await page.mouse.wheel(0, -300);
  await page.waitForTimeout(50);
  t.zoomed = before !== (await page.evaluate(() => document.getElementById("topo-inner").style.transform));
  await page.click("#reset-btn");
  await page.click("#theme-toggle");
  t.theme = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
  if (shots) {
    await page.click("#flow-toggle");
    await page.click("#flow-toggle");
    await page.screenshot({ path: shots + "/topology-light.png" });
  }
  t.csp = await page.evaluate(() => window.__csp);
  t.errors = errors;
  out.topology = t;
  await page.close();
}
// ── dataflow ──
{
  const { page, errors } = await open(dfPath, "dark");
  const d = {};
  const visible = () => page.locator(".flow-row:not(.dimmed)").count();
  d.rows = await page.locator(".flow-row").count();
  if (shots) await page.screenshot({ path: shots + "/dataflow.png", fullPage: false });
  await page.fill("#filter-input", "allow");
  d.filtered = await visible();
  await page.keyboard.press("Escape");
  d.afterEsc = await visible();
  await page.click('[data-state-filter="planned"]');
  d.planned = await visible();
  d.plannedStates = await page.$$eval(".flow-row:not(.dimmed)", (rs) => [...new Set(rs.map((r) => r.dataset.state))]);
  await page.click('[data-state-filter="all"]');
  await page.locator(".group-title").first().click();
  d.groupCollapsed = await page.locator(".df-rows.collapsed").count();
  d.evilRows = await page.locator(".flow-row", { hasText: "evil-1" }).count();
  d.pwned = await page.evaluate(() => window.__pwned === undefined ? null : window.__pwned);
  if (shots) {
    await page.locator(".group-title").first().click();
    await page.locator(".df-group").nth(2).scrollIntoViewIfNeeded();
    await page.screenshot({ path: shots + "/dataflow-hosts.png" });
  }
  d.csp = await page.evaluate(() => window.__csp);
  d.errors = errors;
  out.dataflow = d;
  await page.close();
}
await browser.close();
console.log(JSON.stringify(out));
