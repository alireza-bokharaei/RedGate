"use strict";
/* global document, window */
// Optional, explicit local self-test. Start an isolated DEMO lab on :8000 first.
// Requires npm ci plus REDGATE_CHROMIUM_EXECUTABLE=/path/to/chromium.
const { chromium } = require("playwright-core");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

(async () => {
  const executablePath = process.env.REDGATE_CHROMIUM_EXECUTABLE;
  assert.ok(executablePath, "Set REDGATE_CHROMIUM_EXECUTABLE to a local Chromium binary. No browser is downloaded by npm ci.");
  const output = path.resolve(__dirname, "../test-results/browser");
  await fs.mkdir(output, { recursive: true, mode: 0o700 });
  const browser = await chromium.launch({ executablePath, headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1480, height: 1000 }, acceptDownloads: true });
    const errors = [], outside = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => {
      if (!request.url().startsWith("http://127.0.0.1:8000/") && !request.url().startsWith("blob:")) outside.push(request.url());
    });
    await page.goto("http://127.0.0.1:8000/", { waitUntil: "networkidle" });
    await page.locator("#whoamiName").filter({ hasText: "op-alice" }).waitFor();
    const labLoaded = page.waitForResponse((response) => response.url().includes("/api/v1/workspace?engagement_id=ENG-LOCAL-LAB") && response.ok());
    await page.locator("#engagementSelect").selectOption("ENG-LOCAL-LAB");
    await labLoaded;
    await page.locator("#wsNewMission").click();
    await page.locator("#wsName").fill("RedGate 2.1.0 · local browser self-test");
    await page.locator("#wsTargets").fill("127.0.0.1");
    await page.locator("#wsScheme").selectOption("http");
    await page.locator("#wsPort").fill("8000");
    await page.locator("#wsPath").fill("/probe/headers");
    await page.locator("#wsGoal").fill("Local self-test only: verify anonymous HTTP evidence and human-reviewed header retests.");
    await page.locator("#wsPlanSubmit").click();
    await page.locator("#wsSelectedName").filter({ hasText: "local browser self-test" }).waitFor();
    await page.locator("#wsStart:not([disabled])").waitFor();
    await page.locator("#wsStart").click();
    await page.waitForFunction(() => document.getElementById("wsStatus").textContent === "completed", undefined, { timeout: 30000 });
    const evidence = page.locator("#wsEvidenceList button");
    await evidence.first().waitFor();
    await evidence.first().click();
    assert.ok((await page.locator("#wsInspector").textContent()).includes('"redacted": true'));
    await page.locator("#wsExplorationMode").click();
    assert.ok(await page.locator('#wsGraph [role="button"]').count() >= 5);
    await page.locator("#wsFindingList .ws-finding-row").filter({ hasText: "Content-Security-Policy" }).locator("button").click();
    await page.locator("#wsMessage").filter({ hasText: "Original verdict unchanged" }).waitFor();
    const pendingDownload = page.waitForEvent("download");
    await page.locator("#wsReport").click();
    const download = await pendingDownload;
    const reportPath = path.join(output, "self-test.md");
    await download.saveAs(reportPath);
    const report = await fs.readFile(reportPath, "utf8");
    assert.ok(report.startsWith("# RedGate 2.1.0") && report.includes("Hashes cover stored, redacted snapshots"));
    await page.locator('#wsGraph [role="button"]').first().focus();
    await page.keyboard.press("Enter");
    assert.ok((await page.locator("#wsInspector").textContent()).includes('"kind": "goal"'));
    await page.screenshot({ path: path.join(output, "desktop.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(output, "mobile.png"), fullPage: true });
    const widths = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: window.innerWidth }));
    assert.ok(widths.document <= widths.viewport + 1, `Mobile overflow: ${JSON.stringify(widths)}`);
    assert.deepEqual(outside, []);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ browser: await browser.version(), mission: "completed", evidence: await evidence.count(), headerRetest: "appended", markdown: "downloaded", keyboard: "passed", mobile: widths, externalRequests: outside.length, javascriptErrors: errors.length }));
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
