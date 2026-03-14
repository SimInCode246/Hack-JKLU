const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);

(async () => {
  const tempDir = path.join(__dirname, 'audit-temp');
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.mkdirSync(tempDir, { recursive: true });
  fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
    name: 'audit-test',
    version: '1.0.0',
    dependencies: { lodash: '4.17.20' }
  }, null, 2));

  console.log('Running npm install --package-lock-only...');
  try {
    await execAsync('npm install --package-lock-only', { cwd: tempDir });
  } catch (err) {
    console.error('lockfile generation error', err.message);
  }

  console.log('Running npm audit --json...');
  try {
    const { stdout } = await execAsync('npm audit --json', { cwd: tempDir });
    const auditResult = JSON.parse(stdout);
    console.log('auditResult keys:', Object.keys(auditResult));
    console.log('vulnerabilities keys:', Object.keys(auditResult.vulnerabilities || {}));

    // Apply same parsing logic as the server
    const rawAdvisories = auditResult.advisories || auditResult.vulnerabilities || {};
    const vulnerabilities = [];

    Object.values(rawAdvisories).forEach((advisory) => {
      if (!advisory) return;

      const viaEntry = Array.isArray(advisory.via)
        ? advisory.via.find((v) => typeof v === 'object') || advisory.via[0]
        : null;

      const name = advisory.module_name || advisory.name || (viaEntry && viaEntry.name);
      const version = advisory.vulnerable_versions || advisory.version || advisory.range;
      const severity = (advisory.severity || (viaEntry && viaEntry.severity) || 'low').toString();
      const title =
        (viaEntry && viaEntry.title) ||
        advisory.title ||
        name ||
        'Vulnerability detected';
      const description = (viaEntry && viaEntry.title) || advisory.overview || '';

      const cveCandidates = [];
      if (viaEntry && Array.isArray(viaEntry.cves)) cveCandidates.push(...viaEntry.cves);
      if (viaEntry && viaEntry.cve) cveCandidates.push(viaEntry.cve);
      if (advisory.cves) cveCandidates.push(...(Array.isArray(advisory.cves) ? advisory.cves : [advisory.cves]));
      if (advisory.cve) cveCandidates.push(advisory.cve);

      const url = (viaEntry && viaEntry.url) || advisory.url;
      if (!cveCandidates.length && typeof url === 'string') {
        const ghsaMatch = url.match(/GHSA-[\w-]+/i);
        if (ghsaMatch) cveCandidates.push(ghsaMatch[0]);
      }

      const cves = cveCandidates.length ? Array.from(new Set(cveCandidates)) : undefined;

      vulnerabilities.push({
        name: name || 'unknown',
        version: version || 'unknown',
        severity: severity.charAt(0).toUpperCase() + severity.slice(1),
        title,
        description,
        cwe: advisory.cwe
          ? Array.isArray(advisory.cwe)
            ? advisory.cwe.map((c) => `CWE-${c}`).join(', ')
            : `CWE-${advisory.cwe}`
          : undefined,
        cves,
        fix:
          (advisory.fixAvailable && advisory.fixAvailable.name)
            ? `Update to ${advisory.fixAvailable.name}`
            : advisory.recommendation || 'Update to a non-vulnerable version',
        url,
        cvss:
          (viaEntry && viaEntry.cvss && viaEntry.cvss.score) ||
          advisory.cvss_score ||
          undefined
      });
    });

    console.log('Parsed vulnerabilities count:', vulnerabilities.length);
    console.log('Sample parsed vuln:', vulnerabilities[0]);
  } catch (err) {
    console.error('audit error code', err.code);
    const stdout = err.stdout || '';
    console.log('stdout (truncated):', stdout.slice(0, 800));
    try {
      const auditResult = JSON.parse(stdout);
      console.log('Parsed auditResult keys:', Object.keys(auditResult));
      const rawAdvisories = auditResult.advisories || auditResult.vulnerabilities || {};
      const parsed = Object.values(rawAdvisories).map((advisory) => {
        const viaEntry = Array.isArray(advisory.via)
          ? advisory.via.find((v) => typeof v === 'object') || advisory.via[0]
          : null;
        return {
          name: advisory.module_name || advisory.name || (viaEntry && viaEntry.name),
          title: (viaEntry && viaEntry.title) || advisory.title,
          url: (viaEntry && viaEntry.url) || advisory.url
        };
      });
      console.log('Parsed advisory summary:', parsed.slice(0, 3));
    } catch (parseErr) {
      console.error('Failed to parse audit output:', parseErr.message);
    }
  }
})();
