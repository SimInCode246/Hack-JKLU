const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const https = require('https');
const { promisify } = require('util');
const { exec } = require('child_process');
const { ESLint } = require('eslint');
const AdmZip = require('adm-zip');
const PDFKit = require('pdfkit');
const xml2js = require('xml2js');

// Ensure the working directory is the backend folder so ESLint plugin resolution works as expected.
process.chdir(__dirname);
const {
  PDFDocument: PDFLibDocument,
  StandardFonts,
  rgb,
  PDFName,
  PDFNumber,
  PDFNull
} = require('pdf-lib');

let openaiClient = null;
try {
  const { Configuration, OpenAIApi } = require('openai');
  if (process.env.OPENAI_API_KEY) {
    const configuration = new Configuration({ apiKey: process.env.OPENAI_API_KEY });
    openaiClient = new OpenAIApi(configuration);
  }
} catch (err) {
  // OpenAI is optional; skip if not installed or configured.
}

const execAsync = promisify(exec);

let cweData = null;

const loadCWEData = async () => {
  if (cweData) return cweData;
  const url = 'https://cwe.mitre.org/data/xml/cwe_latest.xml';
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        xml2js.parseString(data, (err, result) => {
          if (err) return reject(err);
          cweData = result.Weakness_Catalog.Weaknesses[0].Weakness;
          resolve(cweData);
        });
      });
    }).on('error', reject);
  });
};

const fetchCWEData = async (cweId) => {
  const data = await loadCWEData();
  const weakness = data.find(w => w.$.ID === cweId);
  if (!weakness) return null;
  
  const mitigations = weakness.Potential_Mitigations;
  let fixes = [];
  if (mitigations && mitigations[0] && mitigations[0].Mitigation) {
    fixes = mitigations[0].Mitigation.map(m => ({
      phase: m.$.Phase || 'Unknown',
      strategy: m.$.Strategy || 'Unknown',
      description: m.Description ? m.Description[0] : 'No description'
    }));
  }
  return {
    id: cweId,
    name: weakness.$.Name,
    description: weakness.Description ? weakness.Description[0] : 'No description',
    fixes
  };
};

const app = express();
const PORT = process.env.PORT || 5000;

const historyFilePath = path.join(__dirname, 'scan-history.json');
const logoPath = path.join(__dirname, 'assets', 'logo.png');
const hasLogoImage = fs.existsSync(logoPath);

const loadHistory = () => {
  try {
    if (!fs.existsSync(historyFilePath)) {
      fs.writeFileSync(historyFilePath, JSON.stringify([]), 'utf8');
      return [];
    }
    const content = fs.readFileSync(historyFilePath, 'utf8');
    return JSON.parse(content || '[]');
  } catch (err) {
    console.error('Failed to load history:', err);
    return [];
  }
};

const exportToCSV = (data, type) => {
  const csvRows = [];
  
  if (type === 'vulnerabilities') {
    // CSV headers for vulnerabilities
    csvRows.push(['Severity', 'Title', 'Description', 'CWE', 'CVEs', 'Fix', 'File', 'Line', 'Column', 'Rule ID', 'Docs URL'].join(','));
    
    data.forEach(item => {
      const row = [
        item.severity || '',
        `"${(item.title || '').replace(/"/g, '""')}"`,
        `"${(item.description || '').replace(/"/g, '""')}"`,
        item.cwe || '',
        `"${(Array.isArray(item.cves) ? item.cves.join('; ') : item.cves || '').replace(/"/g, '""')}"`,
        `"${(item.fix || '').replace(/"/g, '""')}"`,
        item.file || '',
        item.line || '',
        item.column || '',
        item.ruleId || '',
        item.docsUrl || ''
      ];
      csvRows.push(row.join(','));
    });
  } else if (type === 'dependencies') {
    // CSV headers for dependencies
    csvRows.push(['Name', 'Version', 'Severity', 'Title', 'Description', 'CWE', 'CVEs', 'Fix', 'URL', 'CVSS Score'].join(','));
    
    data.forEach(item => {
      const row = [
        item.name || '',
        item.version || '',
        item.severity || '',
        `"${(item.title || '').replace(/"/g, '""')}"`,
        `"${(item.description || '').replace(/"/g, '""')}"`,
        item.cwe || '',
        `"${(Array.isArray(item.cves) ? item.cves.join('; ') : item.cve || '').replace(/"/g, '""')}"`,
        `"${(item.fix || '').replace(/"/g, '""')}"`,
        item.url || '',
        item.cvss || ''
      ];
      csvRows.push(row.join(','));
    });
  }
  
  return csvRows.join('\n');
};

const saveHistory = (history) => {
  try {
    fs.writeFileSync(historyFilePath, JSON.stringify(history, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save history:', err);
  }
};

const appendHistory = (entry) => {
  const history = loadHistory();
  history.unshift(entry);
  if (history.length > 100) history.splice(100);
  saveHistory(history);
};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// Sample vulnerability data (fallback)
const sampleVulnerabilities = [
  {
    severity: 'High',
    title: 'SQL Injection',
    description: 'Potential SQL injection vulnerability detected',
    cwe: 'CWE-89',
    fix: 'Use parameterized queries or prepared statements',
    line: 10
  },
  {
    severity: 'Medium',
    title: 'Cross-Site Scripting (XSS)',
    description: 'Unescaped user input in HTML output',
    cwe: 'CWE-79',
    fix: 'Sanitize user input and use Content Security Policy',
    line: 25
  }
];

const aiHeuristicPatterns = [
  {
    id: 'unsafe-innerhtml',
    title: 'Unsafe use of innerHTML',
    description: 'Assigning to innerHTML can lead to cross-site scripting (XSS) if user-controlled content is injected.',
    fix: 'Use safer DOM APIs like textContent or a templating library that auto-escapes user input.',
    regex: /innerHTML\s*=/i,
    severity: 'High',
    confidence: 'High'
  },
  {
    id: 'unsafe-document-write',
    title: 'Unsafe use of document.write',
    description: 'document.write can be abused to inject malicious scripts and is generally unsafe in modern web apps.',
    fix: 'Avoid document.write; use DOM manipulation or templating instead.',
    regex: /document\.write\s*\(/i,
    severity: 'High',
    confidence: 'High'
  },
  {
    id: 'unsafe-exec',
    title: 'Command execution via exec()',
    description: 'Using exec() can run arbitrary shell commands; do not execute user-provided input.',
    fix: 'Avoid exec(); use safer alternatives or validate/whitelist input before executing.',
    regex: /(?:\bexec\s*\(|child_process\.exec\s*\()/i,
    severity: 'High',
    confidence: 'High'
  },
  {
    id: 'unsafe-eval',
    title: 'Unsafe use of eval()',
    description: 'eval() can execute arbitrary strings as code, which is dangerous when used with untrusted input.',
    fix: 'Avoid eval(); use safer alternatives or parse expressions safely.',
    regex: /\beval\s*\(/i,
    severity: 'High',
    confidence: 'High'
  },
  {
    id: 'ssrf-http-request',
    title: 'Server-Side Request Forgery (SSRF)',
    description: 'Making HTTP requests to user-controlled URLs can allow attackers to access internal resources.',
    fix: 'Validate and whitelist allowed URLs, or use a safe HTTP client that prevents access to internal resources.',
    regex: /(?:https?\.request|fetch|axios\.get|axios\.post|request\s*\()\s*.*(?:req\.|userInput|url)/i,
    severity: 'High',
    confidence: 'Medium'
  },
  {
    id: 'insecure-deserialization',
    title: 'Insecure Deserialization',
    description: 'Deserializing untrusted data can lead to remote code execution or other attacks.',
    fix: 'Use safe deserialization methods, validate input, or avoid deserializing untrusted data.',
    regex: /(?:JSON\.parse|unserialize|pickle\.loads|yaml\.load|ObjectInputStream)/i,
    severity: 'High',
    confidence: 'Medium'
  },
  {
    id: 'hardcoded-secret',
    title: 'Hardcoded Secret',
    description: 'API keys, passwords, or other secrets are hardcoded in the source code.',
    fix: 'Move secrets to environment variables or a secure configuration management system.',
    regex: /(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"][^'"]{10,}['"]/i,
    severity: 'High',
    confidence: 'High'
  },
  {
    id: 'sql-injection',
    title: 'Potential SQL Injection',
    description: 'String concatenation in SQL queries can lead to SQL injection vulnerabilities.',
    fix: 'Use parameterized queries or prepared statements.',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+.*(?:req\.|userInput)/i,
    severity: 'High',
    confidence: 'Medium'
  },
  {
    id: 'path-traversal',
    title: 'Path Traversal',
    description: 'User input used in file paths without proper validation can allow directory traversal attacks.',
    fix: 'Validate and sanitize file paths, use allowlists, or resolve paths safely.',
    regex: /(?:fs\.|path\.|readFile|writeFile)\s*\(\s*.*(?:req\.|userInput)/i,
    severity: 'High',
    confidence: 'Medium'
  },
  {
    id: 'weak-crypto',
    title: 'Weak Cryptographic Algorithm',
    description: 'Using weak or deprecated cryptographic algorithms that can be easily broken.',
    fix: 'Use strong, modern cryptographic algorithms like AES-256, SHA-256, or bcrypt.',
    regex: /(?:md5|sha1|des|rc4)\s*\(/i,
    severity: 'Medium',
    confidence: 'High'
  },
  {
    id: 'insecure-random',
    title: 'Insecure Random Number Generation',
    description: 'Using Math.random() for security-sensitive operations is predictable and insecure.',
    fix: 'Use crypto.randomBytes() or a cryptographically secure random number generator.',
    regex: /Math\.random\s*\(/i,
    severity: 'Medium',
    confidence: 'High'
  },
  {
    id: 'debug-enabled',
    title: 'Debug Information Leakage',
    description: 'Debug mode or verbose error messages may leak sensitive information.',
    fix: 'Disable debug mode in production and sanitize error messages.',
    regex: /(?:debug\s*=\s*true|NODE_ENV\s*=\s*['"]development['"])/i,
    severity: 'Medium',
    confidence: 'Low'
  },
  {
    id: 'unsafe-redirect',
    title: 'Unsafe Redirect',
    description: 'Redirecting to user-controlled URLs can lead to open redirect vulnerabilities.',
    fix: 'Validate redirect URLs against a whitelist of allowed domains.',
    regex: /(?:res\.redirect|window\.location)\s*\(\s*.*(?:req\.|userInput)/i,
    severity: 'Medium',
    confidence: 'Medium'
  },
  {
    id: 'missing-helmet',
    title: 'Missing Security Headers',
    description: 'Security headers like Helmet are not being used to protect against common attacks.',
    fix: 'Install and use the Helmet middleware to set security headers.',
    regex: /(?:app\.use\s*\(\s*helmet|helmet\s*\()/i,
    severity: 'Low',
    invert: true, // This pattern should NOT match for it to be a vulnerability
    confidence: 'High'
  }
];

const runAIAnalysis = async (code, filename) => {
  // If OpenAI is configured, use it. Otherwise use heuristic patterns.
  if (openaiClient) {
    try {
      const prompt = `You are a security analysis assistant. Analyze the following JavaScript/TypeScript code for security vulnerabilities, risky patterns, and potential CVEs if known. Return the output as valid JSON array of objects with fields: title, description, severity (High/Medium/Low), file, line, cve (optional), fix (optional). Only output JSON.`;
      const response = await openaiClient.createChatCompletion({
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: prompt },
          { role: 'user', content: `Filename: ${filename}\n\n${code}` }
        ],
        temperature: 0.2,
        max_tokens: 700
      });
      const text = response.data.choices?.[0]?.message?.content?.trim();
      if (!text) return [];

      // Attempt JSON parse; best effort.
      try {
        return JSON.parse(text);
      } catch {
        // Fallback to heuristic if OpenAI output is not valid JSON
      }
    } catch (err) {
      // If OpenAI request fails, fall back to heuristic patterns
      console.error('OpenAI analysis failed:', err?.message || err);
    }
  }

  // Heuristic scan if OpenAI is unavailable or fails
  const vulnerabilities = [];
  aiHeuristicPatterns.forEach((pattern) => {
    const matches = pattern.regex.test(code);
    const shouldReport = pattern.invert ? !matches : matches;
    if (shouldReport) {
      vulnerabilities.push({
        file: filename,
        severity: pattern.severity,
        title: pattern.title,
        description: pattern.description,
        line: 1,
        fix: pattern.fix,
        cve: undefined,
        confidence: pattern.confidence || 'Medium'
      });
    }
  });

  return vulnerabilities;
};

const eslint = new ESLint({
  // Ensure ESLint resolves plugins relative to the backend folder
  resolvePluginsRelativeTo: __dirname,
  overrideConfig: {
    env: { node: true, es2021: true },
    parserOptions: { ecmaVersion: 2021, sourceType: 'module' },
    plugins: ['security'],
    rules: {
      // Basic security-focused ESLint rules
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-script-url': 'error',
      'no-unsafe-finally': 'error',
      // ESLint Security plugin rules
      'security/detect-eval-with-expression': 'error',
      'security/detect-non-literal-require': 'warn',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-child-process': 'warn',
      'security/detect-object-injection': 'warn',
      'security/detect-unsafe-regex': 'warn'
    }
  },
  overrideConfigFile: null
});

// Sample dependencies data
const sampleDependencies = [
  {
    name: 'express',
    version: '4.18.2',
    severity: 'Low',
    description: 'Known vulnerability in older versions'
  },
  {
    name: 'lodash',
    version: '4.17.20',
    severity: 'Medium',
    description: 'Prototype pollution vulnerability'
  }
];

// API Routes
app.get('/api', (req, res) => {
  res.json({
    status: 'OK',
    message: 'API root',
    routes: [
      { method: 'GET', path: '/api/health' },
      { method: 'GET', path: '/api/history' },
      { method: 'DELETE', path: '/api/history' },
      { method: 'POST', path: '/api/scan/code' },
      { method: 'POST', path: '/api/scan/dependencies' },
      { method: 'POST', path: '/api/scan/repo' },
      { method: 'POST', path: '/api/scan/github' },
      { method: 'GET', path: '/api/dashboard/stats' },
      { method: 'GET', path: '/docs' }
    ]
  });
});

app.get('/docs', (req, res) => {
  const docsHtml = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>API Docs</title>
        <style>
          body { font-family: system-ui, sans-serif; background: #0b0e14; color: #e2e8f0; margin: 0; padding: 24px; }
          h1 { margin-bottom: 12px; }
          table { width: 100%; border-collapse: collapse; margin-top: 16px; }
          th, td { padding: 12px 10px; text-align:left; }
          th { background: rgba(148, 163, 184, 0.15); }
          tr:nth-child(even) { background: rgba(148, 163, 184, 0.08); }
          code { background: rgba(148, 163, 184, 0.12); padding: 2px 6px; border-radius: 4px; }
        </style>
      </head>
      <body>
        <h1>Security Scanner API Docs</h1>
        <p>Available endpoints for the backend API.</p>
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>GET</td><td><code>/api</code></td><td>API root listing routes</td></tr>
            <tr><td>GET</td><td><code>/docs</code></td><td>This documentation page</td></tr>
            <tr><td>GET</td><td><code>/api/health</code></td><td>Health check</td></tr>
            <tr><td>GET</td><td><code>/api/history</code></td><td>Retrieve scan history (persisted)</td></tr>
            <tr><td>DELETE</td><td><code>/api/history</code></td><td>Clear scan history</td></tr>
            <tr><td>POST</td><td><code>/api/scan/code</code></td><td>Scan provided code for vulnerabilities</td></tr>
            <tr><td>POST</td><td><code>/api/scan/dependencies</code></td><td>Scan dependencies (package.json) for issues</td></tr>
            <tr><td>POST</td><td><code>/api/scan/repo</code></td><td>Scan entire repository (ZIP) for code and dependency vulnerabilities</td></tr>
            <tr><td>GET</td><td><code>/api/dashboard/stats</code></td><td>Mock dashboard statistics</td></tr>
          </tbody>
        </table>
      </body>
    </html>
  `;
  res.type('html').send(docsHtml);
});

app.get('/api/history', (req, res) => {
  const history = loadHistory();
  res.json({ history });
});

app.delete('/api/history', (req, res) => {
  saveHistory([]);
  res.json({ message: 'History cleared' });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Backend is running' });
});

const detectLanguageSuggestion = (code) => {
  const lower = code.toLowerCase();
  if (/<\?php/.test(code)) {
    return 'Detected PHP code. Use a PHP security scanner like phpstan/phpcs-security or roave/security-advisories.';
  }
  if (/^\s*#\s*include/m.test(code) || /\bprintf\s*\(/.test(code) || /\bgets\s*\(/.test(code)) {
    return 'Detected C/C++ code. Try a C/C++ security analyzer such as cppcheck or clang-tidy.';
  }
  if (/\bdef\s+\w+\s*\(/.test(code) || /\bimport\s+\w+/.test(lower)) {
    return 'Detected Python code. Consider using bandit, semgrep, or a Python static analysis tool.';
  }
  if (/\bpublic\s+class\b/.test(code) || /\bSystem\.out\./.test(code)) {
    return 'Detected Java code. Consider using SpotBugs, PMD, or Semgrep for Java security scans.';
  }
  if (/^\s*#!/.test(code)) {
    return 'Detected a shell script. Use ShellCheck or Semgrep to scan shell scripts.';
  }
  return null;
};

app.post('/api/scan/code', async (req, res) => {
  const { code, filename } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Missing required `code` field in request body' });
  }

  const scanTime = new Date().toISOString();

  try {
    const lintResults = await eslint.lintText(code, {
      filePath: filename || 'input.js'
    });

    const vulnerabilities = [];

    lintResults.forEach((result) => {
      result.messages.forEach((msg) => {
        // Convert ESLint message to our vulnerability format
        // Provide a generic remediation for parsing errors when ESLint cannot parse the source
        let fixText = msg.fix ? msg.fix.text : undefined;
        if (!fixText && msg.message && /Parsing error/i.test(msg.message)) {
          const suggestion = detectLanguageSuggestion(code);
          fixText =
            'This likely means the code is not valid JavaScript/TypeScript or uses syntax not supported by the scanner.' +
            (suggestion ? ` ${suggestion}` : ' Use a language-specific scanner for other languages (e.g., Python, PHP, C).');
        }

        vulnerabilities.push({
          severity: msg.severity === 2 ? 'High' : 'Medium',
          ruleId: msg.ruleId,
          title: msg.ruleId || 'Security issue detected',
          description: msg.message,
          line: msg.line,
          column: msg.column,
          fix: fixText,
          docsUrl: msg.ruleId
            ? `https://eslint.org/docs/rules/${msg.ruleId}`
            : undefined
        });
      });
    });

    // Additional pattern-based detections (for things ESLint may not flag)
    aiHeuristicPatterns.forEach((pattern) => {
      const matches = pattern.regex.test(code);
      const shouldReport = pattern.invert ? !matches : matches;
      if (shouldReport) {
        vulnerabilities.push({
          severity: pattern.severity,
          ruleId: pattern.id,
          title: pattern.title,
          description: pattern.description,
          line: 1,
          column: 1,
          fix: pattern.fix,
          docsUrl: undefined,
          confidence: pattern.confidence || 'Medium'
        });
      }
    });

    // Additional AI-assisted analysis (optional OpenAI integration)
    const aiFindings = await runAIAnalysis(code, filename || 'input.js');

    const highCount = vulnerabilities.filter(v => v.severity === 'High').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'Medium').length;
    const riskScore = Math.min(100, highCount * 40 + mediumCount * 20);

    const result = {
      vulnerabilities,
      aiFindings,
      riskScore,
      scanTime
    };

    appendHistory({
      id: Date.now().toString(),
      type: 'code',
      timestamp: scanTime,
      input: { snippet: code.slice(0, 500) },
      result
    });

    res.json(result);
  } catch (error) {
    console.error('Error during code scan:', error);

    // Fallback to the sample vulnerabilities if linting fails
    const result = {
      vulnerabilities: sampleVulnerabilities,
      aiFindings: [],
      riskScore: 75,
      scanTime
    };

    appendHistory({
      id: Date.now().toString(),
      type: 'code',
      timestamp: scanTime,
      input: { snippet: code.slice(0, 500) },
      result,
      error: error.message
    });

    res.status(500).json({
      error: 'Code scan failed',
      details: error.message,
      result
    });
  }
});

const detectPackageManager = (content, filename) => {
  const lowerFilename = filename.toLowerCase();
  
  if (lowerFilename === 'package.json' || lowerFilename.endsWith('.json')) {
    try {
      const pkg = JSON.parse(content);
      if (pkg.dependencies || pkg.devDependencies) {
        return 'npm';
      }
    } catch (e) {}
  }
  
  if (lowerFilename === 'requirements.txt' || lowerFilename === 'pipfile' || 
      lowerFilename === 'pyproject.toml' || lowerFilename === 'poetry.lock') {
    return 'python';
  }
  
  if (lowerFilename === 'gemfile' || lowerFilename === 'gemfile.lock') {
    return 'ruby';
  }
  
  if (lowerFilename === 'composer.json') {
    return 'php';
  }
  
  if (lowerFilename === 'pom.xml') {
    return 'maven';
  }
  
  if (lowerFilename.endsWith('.csproj') || lowerFilename === 'packages.config') {
    return 'nuget';
  }
  
  // Fallback: try to detect from content
  if (content.includes('"dependencies"') || content.includes("'dependencies'")) {
    return 'npm';
  }
  
  return 'unknown';
};

const scanNpmDependencies = async (packageJsonContent) => {
  // Existing npm audit logic
  const tempDir = path.join(os.tmpdir(), `audit-${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });

  const packageJsonPath = path.join(tempDir, 'package.json');
  fs.writeFileSync(packageJsonPath, packageJsonContent, 'utf8');

  try {
    await execAsync('npm install --package-lock-only', { cwd: tempDir });
  } catch (lockErr) {
    console.warn('Unable to generate lockfile for audit (continuing):', lockErr?.message || lockErr);
  }

  let auditResult;
  try {
    const { stdout } = await execAsync('npm audit --json', { cwd: tempDir });
    auditResult = JSON.parse(stdout);
  } catch (auditErr) {
    if (auditErr && auditErr.stdout) {
      try {
        auditResult = JSON.parse(auditErr.stdout);
      } catch (parseErr) {
        throw auditErr;
      }
    } else {
      throw auditErr;
    }
  }

  fs.rmSync(tempDir, { recursive: true, force: true });

  const vulnerabilities = [];
  const rawAdvisories = auditResult.advisories || auditResult.vulnerabilities || {};

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

  const totalDependencies =
    auditResult.metadata?.dependencies?.total ??
    auditResult.metadata?.totalDependencies ??
    0;
  const vulnerableCount =
    auditResult.metadata?.vulnerabilities?.total ??
    vulnerabilities.length;

  return { vulnerabilities, totalDependencies, vulnerableCount };
};

const scanPythonDependencies = async (content, filename) => {
  const tempDir = path.join(os.tmpdir(), `python-audit-${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });

  const filePath = path.join(tempDir, filename);
  fs.writeFileSync(filePath, content, 'utf8');

  try {
    // Try pip-audit if available
    const { stdout } = await execAsync(`pip-audit --format json --file ${filePath}`, { cwd: tempDir });
    const auditResult = JSON.parse(stdout);
    
    const vulnerabilities = auditResult.map(item => ({
      name: item.name,
      version: item.version,
      severity: item.severity || 'Unknown',
      title: item.vuln ? item.vuln.description : `Vulnerability in ${item.name}`,
      description: item.vuln ? item.vuln.description : '',
      cves: item.vuln && item.vuln.aliases ? item.vuln.aliases.filter(alias => alias.startsWith('CVE-')) : undefined,
      fix: item.fix ? `Update to ${item.fix.version}` : 'Update to a non-vulnerable version',
      url: item.vuln ? item.vuln.references?.[0] : undefined
    }));

    fs.rmSync(tempDir, { recursive: true, force: true });
    return { vulnerabilities, totalDependencies: vulnerabilities.length, vulnerableCount: vulnerabilities.length };
  } catch (err) {
    console.warn('pip-audit failed, falling back to basic parsing:', err.message);
    
    // Fallback: basic parsing without audit
    const lines = content.split('\n');
    const dependencies = lines
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'))
      .map(line => {
        const match = line.match(/^([a-zA-Z0-9\-_.]+)([=<>!~]+.+)?$/);
        if (match) {
          return { name: match[1], version: match[2] || 'latest' };
        }
        return null;
      })
      .filter(Boolean);

    fs.rmSync(tempDir, { recursive: true, force: true });
    return { 
      vulnerabilities: [], 
      totalDependencies: dependencies.length, 
      vulnerableCount: 0,
      note: 'pip-audit not available. Install with: pip install pip-audit'
    };
  }
};

const scanRubyDependencies = async (content, filename) => {
  const tempDir = path.join(os.tmpdir(), `ruby-audit-${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });

  const filePath = path.join(tempDir, filename);
  fs.writeFileSync(filePath, content, 'utf8');

  try {
    // Try bundler-audit if available
    const { stdout } = await execAsync('bundler-audit check --format json', { cwd: tempDir });
    const auditResult = JSON.parse(stdout);
    
    const vulnerabilities = auditResult.results.map(item => ({
      name: item.gem,
      version: item.version,
      severity: item.cve ? 'High' : 'Medium',
      title: item.title || `Vulnerability in ${item.gem}`,
      description: item.description || '',
      cves: item.cve ? [item.cve] : undefined,
      fix: item.unaffected_versions ? `Update to ${item.unaffected_versions}` : 'Update to a non-vulnerable version',
      url: item.url
    }));

    fs.rmSync(tempDir, { recursive: true, force: true });
    return { vulnerabilities, totalDependencies: auditResult.results.length, vulnerableCount: vulnerabilities.length };
  } catch (err) {
    console.warn('bundler-audit failed, falling back to basic parsing:', err.message);
    
    // Fallback: basic parsing
    const lines = content.split('\n');
    const dependencies = lines
      .map(line => line.trim())
      .filter(line => line.startsWith('gem '))
      .map(line => {
        const match = line.match(/gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/);
        if (match) {
          return { name: match[1], version: match[2] || 'latest' };
        }
        return null;
      })
      .filter(Boolean);

    fs.rmSync(tempDir, { recursive: true, force: true });
    return { 
      vulnerabilities: [], 
      totalDependencies: dependencies.length, 
      vulnerableCount: 0,
      note: 'bundler-audit not available. Install with: gem install bundler-audit'
    };
  }
};

app.post('/api/scan/dependencies', upload.single('file'), async (req, res) => {
  let content = req.body.packageJson || req.body.content;
  let filename = req.body.filename || 'package.json';

  if (req.file) {
    // Handle file upload
    const filePath = req.file.path;
    const ext = path.extname(req.file.originalname).toLowerCase();
    filename = req.file.originalname;

    if (ext === '.zip') {
      // Extract ZIP
      const zip = new AdmZip(filePath);
      const tempDir = path.join(os.tmpdir(), `extract-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });
      zip.extractAllTo(tempDir, true);

      // Find dependency files
      const possibleFiles = [
        'package.json', 'requirements.txt', 'Pipfile', 'pyproject.toml', 
        'Gemfile', 'composer.json', 'pom.xml'
      ];
      
      let foundFile = null;
      for (const file of possibleFiles) {
        const filePath = path.join(tempDir, file);
        if (fs.existsSync(filePath)) {
          content = fs.readFileSync(filePath, 'utf8');
          filename = file;
          foundFile = file;
          break;
        }
      }

      if (!foundFile) {
        fs.rmSync(tempDir, { recursive: true, force: true });
        fs.unlinkSync(filePath);
        return res.status(400).json({ error: 'No supported dependency file found in uploaded ZIP' });
      }

      fs.rmSync(tempDir, { recursive: true, force: true });
    } else {
      // Direct file upload
      content = fs.readFileSync(filePath, 'utf8');
    }

    fs.unlinkSync(filePath); // Clean up uploaded file
  }

  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'Missing dependency file content' });
  }

  const scanTime = new Date().toISOString();
  const packageManager = detectPackageManager(content, filename);

  try {
    let result;

    switch (packageManager) {
      case 'npm':
        result = await scanNpmDependencies(content);
        break;
      case 'python':
        result = await scanPythonDependencies(content, filename);
        break;
      case 'ruby':
        result = await scanRubyDependencies(content, filename);
        break;
      default:
        // Fallback: try to parse as JSON (npm style)
        try {
          const parsed = JSON.parse(content);
          if (parsed.dependencies || parsed.devDependencies) {
            result = await scanNpmDependencies(content);
          } else {
            throw new Error('Unsupported format');
          }
        } catch (e) {
          return res.status(400).json({ 
            error: `Unsupported package manager format. Detected: ${packageManager}. Supported: npm, pip, bundler` 
          });
        }
    }

    result.scanTime = scanTime;
    result.packageManager = packageManager;

    appendHistory({
      id: Date.now().toString(),
      type: 'dependencies',
      timestamp: scanTime,
      input: { filename, contentSnippet: content.slice(0, 500) },
      result
    });

    res.json(result);
  } catch (error) {
    console.error('Error during dependency scan:', error);

    // Fallback to sample data if audit fails
    const result = {
      dependencies: sampleDependencies,
      totalDependencies: sampleDependencies.length,
      vulnerableCount: sampleDependencies.filter(d => d.severity !== 'Low').length,
      scanTime,
      packageManager: 'unknown',
      error: error.message
    };

    appendHistory({
      id: Date.now().toString(),
      type: 'dependencies',
      timestamp: scanTime,
      input: { filename, contentSnippet: content.slice(0, 500) },
      result,
      error: error.message
    });

    res.status(500).json({
      error: 'Dependency scan failed',
      details: error.message,
      result
    });
  }
});

const downloadFile = (url, dest, maxRedirects = 5) => {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error('Too many redirects while downloading file'));
    }

    const request = https.get(url, { headers: { 'User-Agent': 'SecureScope' } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        const location = res.headers.location;
        if (!location) {
          return reject(new Error('Redirect response missing Location header'));
        }
        return resolve(downloadFile(location, dest, maxRedirects - 1));
      }

      if (res.statusCode !== 200) {
        return reject(new Error(`Download failed with status ${res.statusCode}`));
      }

      const fileStream = fs.createWriteStream(dest);
      res.pipe(fileStream);
      fileStream.on('finish', () => fileStream.close(resolve));
      fileStream.on('error', (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
    });

    request.on('error', (err) => {
      fs.unlink(dest, () => {});
      reject(err);
    });
  });
};

const scanRepoZip = async (filePath, originalName) => {
  const scanTime = new Date().toISOString();

  // Validate ZIP extension (some GitHub downloads may include query strings)
  const ext = path.extname(originalName).toLowerCase();
  if (!ext || ext !== '.zip') {
    throw new Error('Only ZIP files are supported for repo scanning');
  }

  // Extract ZIP
  const zip = new AdmZip(filePath);
  const tempDir = path.join(os.tmpdir(), `repo-scan-${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });
  zip.extractAllTo(tempDir, true);

  // Find all JS/TS files
  const codeFiles = [];
  const walkDir = (dir) => {
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      if (stat.isDirectory() && !file.startsWith('.') && file !== 'node_modules') {
        walkDir(filePath);
      } else if (stat.isFile() && /\.(js|ts|jsx|tsx)$/.test(file)) {
        codeFiles.push(filePath);
      }
    }
  };
  walkDir(tempDir);

  // Scan code files
  const allVulnerabilities = [];
  const aiFindings = [];
  let totalRiskScore = 0;
  let fileCount = 0;

  for (const codeFile of codeFiles.slice(0, 20)) { // Limit to 20 files for performance
    try {
      const code = fs.readFileSync(codeFile, 'utf8');
      const relativePath = path.relative(tempDir, codeFile);
      const lintResults = await eslint.lintText(code, { filePath: relativePath });

      lintResults.forEach((result) => {
        result.messages.forEach((msg) => {
          allVulnerabilities.push({
            file: relativePath,
            severity: msg.severity === 2 ? 'High' : 'Medium',
            ruleId: msg.ruleId,
            title: msg.ruleId || 'Security issue detected',
            description: msg.message,
            line: msg.line,
            column: msg.column,
            fix: msg.fix ? msg.fix.text : undefined,
            docsUrl: msg.ruleId ? `https://eslint.org/docs/rules/${msg.ruleId}` : undefined
          });
        });
      });

      // Include optional AI-assisted findings (OpenAI or heuristic)
      const fileAiFindings = await runAIAnalysis(code, relativePath);
      aiFindings.push(...fileAiFindings);

      fileCount++;
    } catch (err) {
      console.error(`Error scanning ${codeFile}:`, err);
    }
  }

  // Scan dependencies if any supported dependency files exist
  let dependencyResults = null;
  const dependencyFiles = [
    { path: path.join(tempDir, 'package.json'), type: 'npm', filename: 'package.json' },
    { path: path.join(tempDir, 'requirements.txt'), type: 'python', filename: 'requirements.txt' },
    { path: path.join(tempDir, 'Pipfile'), type: 'python', filename: 'Pipfile' },
    { path: path.join(tempDir, 'pyproject.toml'), type: 'python', filename: 'pyproject.toml' },
    { path: path.join(tempDir, 'Gemfile'), type: 'ruby', filename: 'Gemfile' },
    { path: path.join(tempDir, 'composer.json'), type: 'php', filename: 'composer.json' }
  ];

  for (const depFile of dependencyFiles) {
    if (fs.existsSync(depFile.path)) {
      try {
        const content = fs.readFileSync(depFile.path, 'utf8');
        let result;

        switch (depFile.type) {
          case 'npm':
            result = await scanNpmDependencies(content);
            break;
          case 'python':
            result = await scanPythonDependencies(content, depFile.filename);
            break;
          case 'ruby':
            result = await scanRubyDependencies(content, depFile.filename);
            break;
          default:
            continue; // Skip unsupported types for now
        }

        if (result && result.vulnerabilities) {
          dependencyResults = {
            ...result,
            packageManager: depFile.type
          };
          break; // Use the first dependency file found
        }
      } catch (err) {
        console.error(`Dependency scan failed for ${depFile.filename}:`, err);
      }
    }
  }

  // Clean up
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.unlinkSync(filePath);

  // Calculate overall risk score
  const highCount = allVulnerabilities.filter(v => v.severity === 'High').length;
  const mediumCount = allVulnerabilities.filter(v => v.severity === 'Medium').length;
  const codeRiskScore = Math.min(100, highCount * 40 + mediumCount * 20);
  const depRiskScore = dependencyResults ? Math.min(100, dependencyResults.vulnerableCount * 25) : 0;
  totalRiskScore = Math.max(codeRiskScore, depRiskScore);

  const result = {
    codeScan: {
      vulnerabilities: allVulnerabilities,
      aiFindings,
      filesScanned: fileCount,
      riskScore: codeRiskScore
    },
    dependencyScan: dependencyResults,
    overallRiskScore: totalRiskScore,
    scanTime
  };

  appendHistory({
    id: Date.now().toString(),
    type: 'repo',
    timestamp: scanTime,
    input: { repoName: originalName },
    result
  });

  return result;
};

app.post('/api/scan/repo', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const result = await scanRepoZip(req.file.path, req.file.originalname);
    res.json(result);
  } catch (error) {
    console.error('Error during repo scan:', error);
    try { fs.unlinkSync(req.file.path); } catch (cleanupError) { /* ignore cleanup failures */ }

    res.status(500).json({
      error: 'Repo scan failed',
      details: error.message,
      result: {
        codeScan: { vulnerabilities: [], aiFindings: [], filesScanned: 0, riskScore: 0 },
        dependencyScan: null,
        overallRiskScore: 0,
        scanTime: new Date().toISOString()
      }
    });
  }
});

app.post('/api/scan/github', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'Missing GitHub repository URL' });
  }

  try {
    const parsed = new URL(url);
    if (!parsed.hostname.includes('github.com')) {
      throw new Error('URL is not a GitHub repository');
    }

    const parts = parsed.pathname.split('/').filter(Boolean);
    if (parts.length < 2) {
      throw new Error('Invalid GitHub repository URL');
    }

    const owner = parts[0];
    const repo = parts[1];
    const branch = parts[3] || 'main';
    const zipUrl = `https://api.github.com/repos/${owner}/${repo}/zipball/${branch}`;
    const tempFile = path.join(os.tmpdir(), `github-repo-${Date.now()}.zip`);

    await downloadFile(zipUrl, tempFile);

    const result = await scanRepoZip(tempFile, `${owner}-${repo}.zip`);
    res.json(result);
  } catch (error) {
    console.error('GitHub scan failed:', error);
    res.status(500).json({ error: 'GitHub repo scan failed', details: error.message });
  }
});

app.post('/api/scan/pdf', async (req, res) => {
  const { scanResult, title, companyName } = req.body;

  if (!scanResult) {
    return res.status(400).json({ error: 'Missing scanResult in request body' });
  }

  const reportTitle = title || 'Security Scan Report';
  const orgName = companyName || 'SecureScope';
  const now = new Date().toISOString();

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  (scanResult.codeScan?.vulnerabilities || []).forEach((v) => {
    const sev = (v.severity || '').toLowerCase();
    if (severityCounts[sev] !== undefined) severityCounts[sev]++;
  });

  // Helper to draw a more informative chart for severity breakdown (stacked bar + donut)
  const drawSeverityChart = (doc, x, y, width, height, counts) => {
    const keys = ['critical', 'high', 'medium', 'low'];
    const colors = {
      critical: '#b91c1c',
      high: '#f97316',
      medium: '#eab308',
      low: '#16a34a'
    };

    const total = keys.reduce((sum, k) => sum + (counts[k] || 0), 0);
    const hasData = total > 0;

    // Title
    doc.fontSize(10).fillColor('#334155');
    doc.text('Severity Breakdown', x, y - 16, { width: width, align: 'left' });

    if (!hasData) {
      doc.fontSize(10).fillColor('#475569');
      doc.text('No vulnerabilities detected.', x, y + 10, { width: width, align: 'left' });
      return;
    }

    const chartHeight = height - 20;
    const stackedBarWidth = width * 0.55;
    const donutSize = Math.min(width * 0.35, chartHeight);

    // Stacked bar chart
    const barX = x;
    const barY = y + 10;
    const barHeight = 18;
    let cursorX = barX;

    keys.forEach((key) => {
      const value = counts[key] || 0;
      if (value <= 0) return;
      const segmentWidth = (value / total) * stackedBarWidth;
      doc.rect(cursorX, barY, segmentWidth, barHeight).fill(colors[key]);
      cursorX += segmentWidth;
    });

    // Border around stacked bar
    doc.save();
    doc.lineWidth(0.5).strokeColor('#94a3b8');
    doc.rect(barX, barY, stackedBarWidth, barHeight).stroke();
    doc.restore();

    // Legend for stacked bar
    let legendY = barY + barHeight + 10;
    const legendX = barX;
    const legendLineHeight = 12;

    keys.forEach((key) => {
      const value = counts[key] || 0;
      if (value === 0) return;
      doc.rect(legendX, legendY - 2, 8, 8).fill(colors[key]);
      doc.fontSize(9).fillColor('#475569');
      doc.text(`${key.toUpperCase()} (${value})`, legendX + 12, legendY - 3);
      legendY += legendLineHeight;
    });

    // Donut chart (right side)
    const donutCenterX = x + stackedBarWidth + 20 + donutSize / 2;
    const donutCenterY = y + 10 + chartHeight / 2;
    const outerRadius = donutSize / 2;
    const innerRadius = outerRadius * 0.55;

    let startAngle = 0;
    keys.forEach((key) => {
      const value = counts[key] || 0;
      if (value <= 0) return;
      const sliceAngle = (value / total) * 360;

      doc.save();
      doc.moveTo(donutCenterX, donutCenterY);
      doc.lineTo(donutCenterX + outerRadius * Math.cos((Math.PI / 180) * startAngle), donutCenterY + outerRadius * Math.sin((Math.PI / 180) * startAngle));
      doc.arc(donutCenterX, donutCenterY, outerRadius, startAngle, startAngle + sliceAngle);
      doc.lineTo(donutCenterX, donutCenterY);
      doc.fill(colors[key]);
      doc.restore();

      startAngle += sliceAngle;
    });

    // Cut out hole to make it a donut
    doc.circle(donutCenterX, donutCenterY, innerRadius).fill('#ffffff');
  };

  // Helper to render common header and footer on each page (easy to override later)
  const drawPageHeader = (doc) => {
    const headerX = hasLogoImage ? 110 : 40;

    if (hasLogoImage) {
      try {
        doc.image(logoPath, 40, 40, { width: 60, height: 60 });
      } catch (err) {
        // Fallback to drawn placeholder if the image cannot be rendered
        doc.rect(40, 40, 60, 60).fill('#0ea5e9');
        doc.fontSize(10).fillColor('#ffffff').text('LOGO', 40, 62, { width: 60, align: 'center' });
      }
    } else {
      doc.rect(40, 40, 60, 60).fill('#0ea5e9');
      doc.fontSize(10).fillColor('#ffffff').text('LOGO', 40, 62, { width: 60, align: 'center' });
    }

    doc.fontSize(10).fillColor('#0f172a');
    doc.text(orgName, headerX, 40, { continued: true });
    doc.fontSize(9).fillColor('#475569');
    doc.text(` • ${reportTitle}`, { continued: false });

    doc.fontSize(14).fillColor('#0f172a');
    doc.text(reportTitle, headerX, 60);

    doc.moveTo(40, 86).lineTo(555, 86).lineWidth(0.5).stroke('#cbd5e1');
    doc.moveDown(2);
  };

  const createPdfBuffer = () =>
    new Promise((resolve, reject) => {
      const buffers = [];
      let currentPage = 0;
      const tocEntries = [];

      const doc = new PDFKit({ margin: 40, size: 'A4', bufferPages: true, autoFirstPage: false });

      doc.on('pageAdded', () => {
        currentPage += 1;
        drawPageHeader(doc);
      });

      doc.on('data', (chunk) => buffers.push(chunk));
      doc.on('error', reject);
      doc.on('end', () => resolve({ buffer: Buffer.concat(buffers), tocEntries, totalPages: currentPage }));

      // Cover page
      doc.addPage();
      doc.fontSize(20).fillColor('#0f172a').text(orgName, { align: 'center' });
      doc.moveDown(0.2);
      doc.fontSize(18).fillColor('#0f172a').text(reportTitle, { align: 'center' });
      doc.moveDown(0.8);
      doc.fontSize(10).fillColor('#475569').text(`Generated: ${now}`, { align: 'center' });
      doc.moveDown(2);
      doc.fontSize(12).fillColor('#334155').text('Security scanning results are summarized in this report. For details, see the table of contents on the next page.', {
        align: 'center',
        lineGap: 4
      });

      // Company logo (use real image if available)
      const logoX = 40;
      const logoY = 220;
      if (hasLogoImage) {
        try {
          doc.image(logoPath, logoX, logoY, { width: 60, height: 60 });
        } catch (error) {
          doc.rect(logoX, logoY, 60, 60).fill('#0ea5e9');
          doc.fontSize(10).fillColor('#ffffff').text('LOGO', logoX, logoY + 22, { width: 60, align: 'center' });
        }
      } else {
        doc.rect(logoX, logoY, 60, 60).fill('#0ea5e9');
        doc.fontSize(10).fillColor('#ffffff').text('LOGO', logoX, logoY + 22, { width: 60, align: 'center' });
      }

      // Table of Contents placeholder
      doc.addPage();
      doc.fontSize(16).fillColor('#0f172a').text('Table of Contents', { underline: true });
      doc.moveDown(1);
      doc.fontSize(10).fillColor('#475569').text('The final PDF will include page numbers for each section once the report is fully generated.', {
        lineGap: 4
      });

      // Start actual content pages and capture TOC entries
      const addSection = (heading, renderFn) => {
        doc.addPage();
        tocEntries.push({ title: heading, page: currentPage });
        doc.moveDown(1);
        doc.fontSize(14).fillColor('#0f172a').text(heading, { underline: true });
        doc.moveDown(0.4);
        renderFn();
      };

      // Summary
      addSection('Summary', () => {
        if (typeof scanResult.overallRiskScore === 'number') {
          doc.fontSize(12).fillColor('#0f172a').text(`Overall Risk Score: ${scanResult.overallRiskScore}/100`);
          doc.moveDown(0.6);
        }

        const totalVulns = scanResult.codeScan?.vulnerabilities?.length ?? 0;
        const totalDeps = scanResult.dependencyScan?.vulnerableCount ?? 0;
        doc.fontSize(11).fillColor('#334155').text(`Code vulnerabilities found: ${totalVulns}`);
        doc.fontSize(11).text(`Vulnerable dependencies found: ${totalDeps}`);
        doc.fontSize(11).text(`Files scanned (code): ${scanResult.codeScan?.filesScanned ?? 0}`);
        doc.moveDown(1);

        // Severity chart
        drawSeverityChart(doc, doc.x, doc.y, 500, 110, severityCounts);
        doc.moveDown(7);
      });

      // Code vulnerabilities
      addSection('Code Scan Vulnerabilities', () => {
        if (scanResult.codeScan?.vulnerabilities?.length) {
          scanResult.codeScan.vulnerabilities.forEach((vuln, idx) => {
            doc.fontSize(11).fillColor('#0f172a').text(`${idx + 1}. ${vuln.title || 'Untitled'} (${(vuln.severity || 'Unknown').toUpperCase()})`);
            doc.moveDown(0.2);
            doc.fontSize(10).fillColor('#334155').text(vuln.description || 'No description provided.', { lineGap: 2 });
            if (vuln.file) doc.text(`File: ${vuln.file}`);
            if (vuln.line) doc.text(`Line: ${vuln.line}`);
            if (vuln.fix) doc.text(`Fix: ${vuln.fix}`);
            if (vuln.docsUrl) doc.text(`Docs: ${vuln.docsUrl}`);
            doc.moveDown(0.8);

            if (doc.y > 720) {
              doc.addPage();
              doc.moveDown(1);
            }
          });
        } else {
          doc.fontSize(10).fillColor('#475569').text('No code vulnerabilities were detected.');
        }
      });

      // AI findings (if available)
      addSection('AI Findings', () => {
        if (scanResult.codeScan?.aiFindings?.length) {
          scanResult.codeScan.aiFindings.forEach((vuln, idx) => {
            doc.fontSize(11).fillColor('#0f172a').text(`${idx + 1}. ${vuln.title || 'Untitled'} (${(vuln.severity || 'Unknown').toUpperCase()})`);
            doc.moveDown(0.2);
            doc.fontSize(10).fillColor('#334155').text(vuln.description || 'No description provided.', { lineGap: 2 });
            if (vuln.cves && vuln.cves.length) {
              doc.text(`CVEs: ${vuln.cves.join(', ')}`);
            }
            if (vuln.fix) doc.text(`Fix: ${vuln.fix}`);
            if (vuln.docsUrl) doc.text(`Docs: ${vuln.docsUrl}`);
            doc.moveDown(0.8);

            if (doc.y > 720) {
              doc.addPage();
              doc.moveDown(1);
            }
          });
        } else {
          doc.fontSize(10).fillColor('#475569').text('No AI-generated findings were produced.');
        }
      });

      // Dependency vulnerabilities
      addSection('Dependency Scan Vulnerabilities', () => {
        if (scanResult.dependencyScan?.dependencies?.length) {
          scanResult.dependencyScan.dependencies.forEach((dep, idx) => {
            doc.fontSize(11).fillColor('#0f172a').text(`${idx + 1}. ${dep.name}@${dep.version} (${(dep.severity || 'Unknown').toUpperCase()})`);
            doc.moveDown(0.2);
            doc.fontSize(10).fillColor('#334155').text(dep.description || 'No description provided.', { lineGap: 2 });
            if (dep.fix) doc.text(`Fix: ${dep.fix}`);
            if (dep.url) doc.text(`URL: ${dep.url}`);
            doc.moveDown(0.8);

            if (doc.y > 720) {
              doc.addPage();
              doc.moveDown(1);
            }
          });
        } else {
          doc.fontSize(10).fillColor('#475569').text('No vulnerable dependencies were detected.');
        }
      });

      // Footer / closing note
      doc.addPage();
      doc.fontSize(12).fillColor('#0f172a').text('Closing Notes', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor('#475569').text(
        'This report is intended for awareness and guidance only. Review the listed issues and apply appropriate patches or mitigations as needed.',
        { lineGap: 4 }
      );

      doc.end();
    });

  try {
    const { buffer, tocEntries } = await createPdfBuffer();

    const pdfDoc = await PDFLibDocument.load(buffer);
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

    // Add page numbers
    const pageCount = pdfDoc.getPageCount();
    for (let i = 0; i < pageCount; i += 1) {
      const page = pdfDoc.getPage(i);
      const { width } = page.getSize();
      const text = `Page ${i + 1} of ${pageCount}`;
      const textWidth = font.widthOfTextAtSize(text, 9);
      page.drawText(text, {
        x: (width - textWidth) / 2,
        y: 25,
        size: 9,
        font,
        color: rgb(0.5, 0.5, 0.5)
      });
    }

    // Fill in the Table of Contents (page 2 assumed to be TOC)
    if (tocEntries.length && pageCount > 1) {
      const tocPage = pdfDoc.getPage(1);
      const { width, height } = tocPage.getSize();
      let y = height - 140;

      const makeGoToLink = (page, x, y, w, h, targetPageIndex) => {
        const targetPage = pdfDoc.getPage(targetPageIndex);
        const targetRef = targetPage.ref;

        const dest = pdfDoc.context.obj([
          targetRef,
          PDFName.of('XYZ'),
          PDFNull,
          PDFNull,
          PDFNull
        ]);

        const action = pdfDoc.context.obj({
          S: PDFName.of('GoTo'),
          D: dest
        });

        const rect = pdfDoc.context.obj([
          PDFNumber.of(x),
          PDFNumber.of(y),
          PDFNumber.of(x + w),
          PDFNumber.of(y + h)
        ]);

        const linkAnnot = pdfDoc.context.obj({
          Type: PDFName.of('Annot'),
          Subtype: PDFName.of('Link'),
          Rect: rect,
          Border: pdfDoc.context.obj([PDFNumber.of(0), PDFNumber.of(0), PDFNumber.of(0)]),
          A: action
        });

        const linkRef = pdfDoc.context.register(linkAnnot);
        const annotsKey = PDFName.of('Annots');
        let annots = tocPage.node.get(annotsKey);
        if (!annots) {
          annots = pdfDoc.context.obj([]);
          tocPage.node.set(annotsKey, annots);
        }

        annots.push(linkRef);
      };

      tocEntries.forEach((entry) => {
        const entryText = `${entry.title}`;
        const entryPage = String(entry.page);
        const entryLine = `${entryText}`;
        const pageNumberWidth = font.widthOfTextAtSize(entryPage, 10);
        const dotWidth = font.widthOfTextAtSize('.', 10);

        // Draw title
        tocPage.drawText(entryLine, {
          x: 60,
          y,
          size: 10,
          font,
          color: rgb(0.1, 0.1, 0.1)
        });

        // Draw page number aligned to right
        tocPage.drawText(entryPage, {
          x: width - 60 - pageNumberWidth,
          y,
          size: 10,
          font,
          color: rgb(0.1, 0.1, 0.1)
        });

        // Draw dotted line between
        const startX = 60 + font.widthOfTextAtSize(entryLine, 10) + 4;
        const endX = width - 60 - pageNumberWidth - 4;
        const dotCount = Math.max(1, Math.floor((endX - startX) / dotWidth));
        const dots = '.'.repeat(dotCount);
        tocPage.drawText(dots, {
          x: startX,
          y,
          size: 10,
          font,
          color: rgb(0.6, 0.6, 0.6)
        });

        // Add clickable area that jumps to the corresponding report page
        // PDF coordinates are bottom-left; drawText uses baseline y so we pad a bit.
        const annotationHeight = 14;
        const annotationY = y - 4;
        const annotationWidth = width - 120;
        makeGoToLink(tocPage, 60, annotationY, annotationWidth, annotationHeight, entry.page - 1);

        y -= 18;
      });
    }

    const finalPdf = await pdfDoc.save();

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${reportTitle.replace(/\s+/g, '_')}.pdf"`);
    res.send(Buffer.from(finalPdf));
  } catch (error) {
    console.error('PDF generation failed:', error);
    res.status(500).json({ error: 'PDF generation failed', details: error.message });
  }
});

app.get('/api/history', (req, res) => {
  const history = loadHistory();
  res.json({ history });
});

app.delete('/api/history', (req, res) => {
  saveHistory([]);
  res.json({ message: 'History cleared' });
});

app.post('/api/history/:id/rerun', async (req, res) => {
  const { id } = req.params;
  const history = loadHistory();
  const entry = history.find(h => h.id === id);
  
  if (!entry) {
    return res.status(404).json({ error: 'History entry not found' });
  }

  try {
    let result;
    
    switch (entry.type) {
      case 'code':
        const codeResp = await fetch(`http://localhost:${PORT}/api/scan/code`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: entry.input.snippet, filename: 'rerun.js' })
        });
        result = await codeResp.json();
        break;
      case 'dependencies':
        const depResp = await fetch(`http://localhost:${PORT}/api/scan/dependencies`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: entry.input.contentSnippet, filename: entry.input.filename || 'package.json' })
        });
        result = await depResp.json();
        break;
      case 'repo':
        // For repo scans, we'd need the original file, so we'll return an error for now
        return res.status(400).json({ error: 'Cannot rerun repo scans - original file not available' });
      default:
        return res.status(400).json({ error: 'Unknown scan type' });
    }

    // Add the new result to history
    const newEntry = {
      id: Date.now().toString(),
      type: entry.type,
      timestamp: new Date().toISOString(),
      input: entry.input,
      result
    };
    appendHistory(newEntry);

    res.json({ success: true, result, newEntry });
  } catch (error) {
    console.error('Error rerunning scan:', error);
    res.status(500).json({ error: 'Failed to rerun scan', details: error.message });
  }
});

app.get('/api/export/:type/:format', (req, res) => {
  const { type, format } = req.params;
  const history = loadHistory();
  
  if (!['vulnerabilities', 'dependencies'].includes(type)) {
    return res.status(400).json({ error: 'Invalid export type. Use "vulnerabilities" or "dependencies"' });
  }
  
  if (!['csv', 'json'].includes(format)) {
    return res.status(400).json({ error: 'Invalid export format. Use "csv" or "json"' });
  }

  let allItems = [];
  
  history.forEach(entry => {
    const result = entry.result || {};
    
    if (type === 'vulnerabilities') {
      // Collect code vulnerabilities
      const codeVulns = result.vulnerabilities || result.codeScan?.vulnerabilities || [];
      allItems.push(...codeVulns);
      
      // Collect AI findings
      const aiFindings = result.aiFindings || result.codeScan?.aiFindings || [];
      allItems.push(...aiFindings);
    } else if (type === 'dependencies') {
      // Collect dependency vulnerabilities
      const deps = result.dependencyScan?.dependencies || [];
      allItems.push(...deps);
    }
  });

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${type}-export.json"`);
    res.json(allItems);
  } else if (format === 'csv') {
    const csv = exportToCSV(allItems, type);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${type}-export.csv"`);
    res.send(csv);
  }
});

app.get('/api/export/dashboard/:format', (req, res) => {
  const { format } = req.params;
  
  if (!['csv', 'json'].includes(format)) {
    return res.status(400).json({ error: 'Invalid export format. Use "csv" or "json"' });
  }

  const history = loadHistory();
  const dashboardData = {
    totalScans: history.length,
    lastScanDate: history.length > 0 ? history[0].timestamp : null,
    severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
    topPackages: [],
    trend: [],
    summary: {
      totalVulnerabilities: 0,
      totalDependencies: 0,
      averageRiskScore: 0,
      resolvedIssues: 0
    }
  };

  // Calculate severity breakdown and other stats
  history.forEach(entry => {
    const result = entry.result || {};
    const codeVulns = result.vulnerabilities || result.codeScan?.vulnerabilities || [];
    const aiFindings = result.aiFindings || result.codeScan?.aiFindings || [];
    const deps = result.dependencyScan?.dependencies || [];
    
    [...codeVulns, ...aiFindings].forEach(vuln => {
      const severity = toSeverityKey(vuln.severity);
      dashboardData.severityBreakdown[severity]++;
      dashboardData.summary.totalVulnerabilities++;
    });
    
    deps.forEach(dep => {
      const severity = toSeverityKey(dep.severity);
      dashboardData.severityBreakdown[severity]++;
      dashboardData.summary.totalDependencies++;
      
      if (!dashboardData.topPackages[dep.name]) {
        dashboardData.topPackages[dep.name] = { count: 0, highestSeverity: 'low' };
      }
      dashboardData.topPackages[dep.name].count++;
      if (severityPriority(severity) > severityPriority(dashboardData.topPackages[dep.name].highestSeverity)) {
        dashboardData.topPackages[dep.name].highestSeverity = severity;
      }
    });
    
    if (result.riskScore || result.codeScan?.riskScore || result.overallRiskScore) {
      const score = result.riskScore || result.codeScan?.riskScore || result.overallRiskScore;
      riskScoreSum += score;
      riskScoreCount++;
    }
  });

  // Convert topPackages object to sorted array
  dashboardData.topPackages = Object.entries(dashboardData.topPackages || {})
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  dashboardData.summary.averageRiskScore = riskScoreCount > 0 ? Math.round(riskScoreSum / riskScoreCount) : 0;
  dashboardData.summary.resolvedIssues = Math.floor(dashboardData.summary.totalVulnerabilities * 0.7);

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="dashboard-export.json"');
    res.json(dashboardData);
  } else if (format === 'csv') {
    // Convert dashboard data to CSV format
    const csvData = [
      ['Metric', 'Value'],
      ['Total Scans', dashboardData.totalScans],
      ['Last Scan Date', dashboardData.lastScanDate || 'N/A'],
      ['Total Vulnerabilities', dashboardData.summary.totalVulnerabilities],
      ['Total Dependencies', dashboardData.summary.totalDependencies],
      ['Average Risk Score', dashboardData.summary.averageRiskScore],
      ['Resolved Issues', dashboardData.summary.resolvedIssues],
      ['Critical Severity', dashboardData.severityBreakdown.critical],
      ['High Severity', dashboardData.severityBreakdown.high],
      ['Medium Severity', dashboardData.severityBreakdown.medium],
      ['Low Severity', dashboardData.severityBreakdown.low]
    ];
    
    const csv = csvData.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="dashboard-export.csv"');
    res.send(csv);
  }
});

app.get('/api/dashboard/stats', (req, res) => {
  // Derive statistics from the persisted scan history
  const history = loadHistory();

  const toSeverityKey = (severity) => {
    if (!severity) return 'low';
    const s = String(severity).toLowerCase();
    if (s.includes('crit')) return 'critical';
    if (s.includes('high')) return 'high';
    if (s.includes('med')) return 'medium';
    return 'low';
  };

  const severityPriority = (severity) => {
    switch (severity) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  };

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const packageCounts = {}; // { name: { count, highestSeverity } }
  let vulnerabilitiesFound = 0;
  let riskScoreSum = 0;
  let riskScoreCount = 0;
  let scansToday = 0;

  const todayISO = new Date().toISOString().slice(0, 10);

  const addVuln = (vuln) => {
    if (!vuln) return;
    const sev = toSeverityKey(vuln.severity);
    vulnerabilitiesFound += 1;
    if (severityCounts[sev] !== undefined) severityCounts[sev] += 1;
  };

  const addDependency = (dep) => {
    if (!dep || !dep.name) return;
    const sev = toSeverityKey(dep.severity);
    const key = dep.name;
    if (!packageCounts[key]) {
      packageCounts[key] = { count: 0, highestSeverity: sev };
    }
    packageCounts[key].count += 1;
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    if (severityOrder.indexOf(sev) > severityOrder.indexOf(packageCounts[key].highestSeverity)) {
      packageCounts[key].highestSeverity = sev;
    }
  };

  history.forEach((entry) => {
    const ts = entry.timestamp ? entry.timestamp.slice(0, 10) : null;
    if (ts === todayISO) scansToday += 1;

    const result = entry.result || {};

    // Count risk scores (overallRiskScore or riskScore)
    const score = typeof result.overallRiskScore === 'number'
      ? result.overallRiskScore
      : typeof result.riskScore === 'number'
      ? result.riskScore
      : null;
    if (score !== null) {
      riskScoreSum += score;
      riskScoreCount += 1;
    }

    // Code scan findings
    const codeVulns = result.vulnerabilities || result.codeScan?.vulnerabilities || [];
    codeVulns.forEach(addVuln);

    // Dependency findings
    const deps = result.dependencyScan?.dependencies || [];
    deps.forEach((dep) => {
      addVuln(dep);
      addDependency(dep);
    });
  });

  const averageRiskScore = riskScoreCount > 0 ? Math.round(riskScoreSum / riskScoreCount) : 0;

  const trend = [];
  // Build a simple trend of the last 7 scans (by timestamp) with total vulnerabilities
  const sortedHistory = [...history].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  const lastSeven = sortedHistory.slice(-7);
  lastSeven.forEach((entry) => {
    const date = entry.timestamp ? entry.timestamp.slice(0, 10) : 'unknown';
    const result = entry.result || {};
    const vulnCount = (result.vulnerabilities || result.codeScan?.vulnerabilities || []).length +
      (result.dependencyScan?.dependencies || []).length;
    trend.push({ date, vulnerabilities: vulnCount });
  });

  const topPackages = Object.entries(packageCounts)
    .map(([name, stats]) => ({ name, ...stats }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  res.json({
    totalScans: history.length,
    vulnerabilitiesFound,
    averageRiskScore,
    scansToday,
    resolvedIssues: Math.floor(vulnerabilitiesFound * 0.7),
    severityBreakdown: severityCounts,
    trend,
    topPackages
  });
});

app.get('/api/cwe/:id', async (req, res) => {
  const cweId = req.params.id;
  try {
    const data = await fetchCWEData(cweId);
    if (!data) {
      return res.status(404).json({ error: 'CWE not found' });
    }
    res.json(data);
  } catch (error) {
    console.error('Error fetching CWE data:', error);
    res.status(500).json({ error: 'Failed to fetch CWE data' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});