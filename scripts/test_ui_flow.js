const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');

(async () => {
  const baseUrl = 'http://localhost:3000';
  const outPdfPath = path.resolve(__dirname, 'ui-flow-report.pdf');

  const browser = await puppeteer.launch({ headless: "new" });
  const page = await browser.newPage();
  page.on('pageerror', (err) => console.error('Page error:', err));
  page.on('console', (msg) => {
    if (msg.type() === 'error') console.error('Console error:', msg.text());
  });
  page.on('request', (req) => {
    if (req.url().includes('/api')) {
      console.log('Network request:', req.method(), req.url());
    }
  });

  // Intercept API responses for debugging and PDF export
  let pdfResponse = null;
  page.on('response', async (response) => {
    const url = response.url();
    if (url.includes('/api/scan')) {
      console.log('Network response:', response.status(), url);
    }
    if (url.includes('/api/scan/pdf')) {
      pdfResponse = response;
    }
  });

  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle2' });

    // Run the code scan
    console.log('...listing buttons');
    const buttonLabels = await page.evaluate(() =>
      Array.from(document.querySelectorAll('button')).map((b) => b.textContent?.trim())
    );
    console.log('...found buttons:', buttonLabels);

    console.log('...waiting for scan response');
    const scanResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/scan/code') && resp.status() === 200,
      { timeout: 30000 }
    );

    // Ensure there's code in the editor so the scan button is enabled
    const textareaInfo = await page.evaluate(() => {
      const textareas = Array.from(document.querySelectorAll('textarea'));
      const ta = textareas[0];
      if (ta) {
        ta.value = "const userInput = 'abc'; eval(userInput);";
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }
      const scanBtn = Array.from(document.querySelectorAll('button')).find((b) => /run.*scan/i.test(b.textContent || ''));
      return {
        textareaCount: textareas.length,
        textareaValue: ta?.value,
        scanButtonDisabled: scanBtn?.disabled || false,
        scanButtonText: scanBtn?.textContent?.trim(),
      };
    });

    console.log('...textarea info', textareaInfo);

    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll('button')).find((b) => /run.*scan/i.test(b.textContent || ''));
      if (btn) btn.click();
    });

    await scanResponsePromise;
    console.log('...scan response received');

    // Give the UI a moment to render scan results
    await new Promise((resolve) => setTimeout(resolve, 1200));
    console.log('...waiting for AI findings link check');

    const hasAIFindings = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('h3')).some((h) => h.textContent?.includes('AI Findings'));
    });
    console.log('...AI findings check complete, result:', hasAIFindings);

    // Navigate to Dependencies tab
    await page.evaluate(() => {
      const depBtn = Array.from(document.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Dependencies');
      if (depBtn) depBtn.click();
    });

    // Wait for dependencies page to render
    await page.waitForSelector('h2', { timeout: 20000 });
    await page.waitForFunction(() => {
      return Array.from(document.querySelectorAll('h2')).some((h) => h.textContent?.includes('Dependency Scanner'));
    }, { timeout: 20000 });

    // Fill in a package.json with a known vuln dependency
    const pkgJson = JSON.stringify({ dependencies: { lodash: '4.17.20' } }, null, 2);
    await page.evaluate((pkg) => {
      const ta = document.querySelector('textarea');
      if (ta) {
        ta.value = pkg;
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }, pkgJson);

    // Click Audit Dependencies
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll('button')).find((b) => /Audit Dependencies/i.test(b.textContent || ''));
      if (btn) btn.click();
    });

    // Wait for CVE links to appear in the dependency table
    await page.waitForSelector('a[href*="nvd.nist.gov/vuln/detail/"]', { timeout: 30000 });
    const cveLinks = await page.$$eval('a[href*="nvd.nist.gov/vuln/detail/"]', (els) => els.map((el) => el.textContent));

    // Return to scanner page and do PDF export
    await page.evaluate(() => {
      const scanBtn = Array.from(document.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Scanner');
      if (scanBtn) scanBtn.click();
    });

    await page.waitForSelector('button', { timeout: 20000 });

    // Trigger PDF export
    await page.evaluate(() => {
      const btn = Array.from(document.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Export PDF Report');
      if (btn) btn.click();
    });

    // Wait for the PDF response to be captured
    const start = Date.now();
    while (!pdfResponse && Date.now() - start < 15000) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    if (!pdfResponse) {
      throw new Error('PDF export request was not observed in network activity');
    }

    const buffer = await pdfResponse.buffer();
    fs.writeFileSync(outPdfPath, buffer);

    console.log('✅ UI flow completed.');
    console.log(' - AI Findings section present:', hasAIFindings);
    console.log(' - Found', cveLinks.length, 'CVE link(s) in the rendered UI.');
    console.log(' - Saved PDF export to', outPdfPath);
  } catch (err) {
    console.error('❌ UI flow failed:', err);
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
