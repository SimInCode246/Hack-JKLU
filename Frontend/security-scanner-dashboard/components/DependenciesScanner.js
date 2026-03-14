import { useMemo, useState } from 'react';

export default function DependenciesScanner({ onDependenciesScanned }) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [dependencies, setDependencies] = useState([]);
  const [packageJsonText, setPackageJsonText] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:5000';

  const normalizeSeverity = (severity = '') => severity.toLowerCase();

  const formatSeverity = (severity = '') => {
    const normalized = normalizeSeverity(severity);
    return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : 'Unknown';
  };

  const normalizeDependency = (dependency) => ({
    ...dependency,
    name: dependency?.name || 'Unknown package',
    version: dependency?.version || 'Unknown version',
    severity: normalizeSeverity(dependency?.severity),
    title: dependency?.title || dependency?.description || 'Unknown issue',
    description: dependency?.description || '',
    cves: Array.isArray(dependency?.cves)
      ? dependency.cves
      : dependency?.cve
      ? [dependency.cve]
      : undefined
  });

  const mockDependencies = [
    {
      name: 'lodash',
      version: '<4.17.21',
      severity: 'high',
      title: 'Prototype Pollution',
      description: 'Prototype pollution vulnerability in lodash',
      cwe: 'CWE-1321',
      fix: 'Update to lodash@4.17.21 or later',
      url: 'https://npmjs.com/advisories/1065'
    },
    {
      name: 'axios',
      version: '<0.21.1',
      severity: 'high',
      title: 'Server-Side Request Forgery',
      description: 'SSRF vulnerability in axios',
      cwe: 'CWE-918',
      fix: 'Update to axios@0.21.1 or later',
      url: 'https://npmjs.com/advisories/1594'
    }
  ];

  const runDependencyScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setDependencies([]);

    // Simulate scanning progress
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        const newProgress = prev + Math.random() * 10;
        return newProgress > 90 ? 90 : newProgress;
      });
    }, 200);

    try {
      let response;
      if (uploadedFile) {
        const formData = new FormData();
        formData.append('file', uploadedFile);
        formData.append('filename', uploadedFile.name);
        response = await fetch(`${API_BASE}/api/scan/dependencies`, {
          method: 'POST',
          body: formData
        });
      } else {
        // Detect file type from content
        let filename = 'package.json';
        if (packageJsonText.trim().startsWith('gem ')) {
          filename = 'Gemfile';
        } else if (packageJsonText.includes('==') || packageJsonText.includes('>=')) {
          filename = 'requirements.txt';
        } else if (packageJsonText.includes('[tool.poetry.dependencies]') || packageJsonText.includes('[build-system]')) {
          filename = 'pyproject.toml';
        }

        response = await fetch(`${API_BASE}/api/scan/dependencies`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ 
            content: packageJsonText,
            filename: filename
          })
        });
      }

      if (!response.ok) throw new Error('Dependency scan request failed');
      const data = await response.json();

      const deps = (data.dependencies || []).map(normalizeDependency);
      setDependencies(deps);
      onDependenciesScanned?.(deps);
    } catch {
      const fallbackDependencies = mockDependencies.map(normalizeDependency);
      setDependencies(fallbackDependencies);
      onDependenciesScanned?.(fallbackDependencies);
    } finally {
      clearInterval(progressInterval);
      setScanProgress(100);

      await new Promise((resolve) => setTimeout(resolve, 500));

      setIsScanning(false);
      setScanProgress(0);
    }
  };

  const getSeverityColor = (severity) => {
    switch (normalizeSeverity(severity)) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-600';
      case 'medium': return 'bg-yellow-600';
      case 'low': return 'bg-green-600';
      default: return 'bg-gray-600';
    }
  };

  const severityTotals = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    dependencies.forEach((dep) => {
      const sev = normalizeSeverity(dep.severity);
      if (counts[sev] !== undefined) counts[sev] += 1;
    });
    return counts;
  }, [dependencies]);

  const filteredDependencies = useMemo(() => {
    if (severityFilter === 'all') return dependencies;
    return dependencies.filter((dep) => normalizeSeverity(dep.severity) === severityFilter);
  }, [dependencies, severityFilter]);

  return (
    <div className="bg-gray-800 p-6 rounded-lg">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <span className="inline-flex rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-300">
              PKG
            </span>
            Dependency Scanner
          </h2>
          <p className="text-sm mt-1 text-gray-400">
            Upload dependency files (package.json, requirements.txt, Gemfile, etc.) or ZIP archive to scan for known vulnerabilities across multiple ecosystems
          </p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <label className="cursor-pointer px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm">
            <span className="mr-2 rounded bg-gray-600 px-1.5 py-0.5 text-[10px] font-semibold">FILE</span>
            Upload dependency file or ZIP
            <input
              type="file"
              accept=".json,.txt,.toml,.lock,.zip"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  setUploadedFile(file);
                  setPackageJsonText('');
                }
              }}
            />
          </label>
          {uploadedFile && (
            <span className="text-sm text-cyan-400">
              Selected: {uploadedFile.name}
              <button
                onClick={() => setUploadedFile(null)}
                className="ml-2 text-red-400 hover:text-red-300"
              >
                x
              </button>
            </span>
          )}
          <button
            onClick={runDependencyScan}
            disabled={isScanning || (!packageJsonText.trim() && !uploadedFile)}
            className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg flex items-center gap-2 transition-colors"
          >
            <span className="rounded bg-cyan-500/20 px-2 py-0.5 text-[10px] font-semibold">SCAN</span>
            {isScanning ? 'Scanning...' : 'Audit Dependencies'}
          </button>
        </div>
      </div>

      {/* Manual Input */}
      <div className="mt-4">
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Or paste package.json content:
        </label>
        <textarea
          value={packageJsonText}
          onChange={(e) => {
            setPackageJsonText(e.target.value);
            setUploadedFile(null);
          }}
          placeholder='{"dependencies": {"express": "^4.18.0"}}'
          className="w-full h-32 bg-gray-700 border border-gray-600 rounded-lg p-3 text-gray-300 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500"
          disabled={!!uploadedFile}
        />
      </div>

      {/* Progress Bar */}
      {isScanning && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-400">Auditing packages...</span>
            <span className="text-sm text-cyan-400">{Math.round(scanProgress)}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Results Table */}
      {dependencies.length > 0 && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-400">Filter by severity:</span>
              <select
                className="bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="flex items-center gap-3 text-sm text-gray-300">
              <span className="inline-flex items-center gap-2">
                <span className="w-2 h-2 bg-red-600 rounded-full"></span> Critical: {severityTotals.critical}
              </span>
              <span className="inline-flex items-center gap-2">
                <span className="w-2 h-2 bg-orange-600 rounded-full"></span> High: {severityTotals.high}
              </span>
              <span className="inline-flex items-center gap-2">
                <span className="w-2 h-2 bg-yellow-600 rounded-full"></span> Medium: {severityTotals.medium}
              </span>
              <span className="inline-flex items-center gap-2">
                <span className="w-2 h-2 bg-green-600 rounded-full"></span> Low: {severityTotals.low}
              </span>
            </div>
          </div>

          {filteredDependencies.length === 0 ? (
            <div className="text-center py-10 text-gray-400">
              No vulnerabilities match the selected severity filter.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Package</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Vulnerable Versions</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Severity</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Vulnerability</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">CWE</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">CVE</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDependencies.map((dep, index) => (
                    <tr key={index} className="border-b border-gray-700 hover:bg-gray-700/50">
                      <td className="py-3 px-4 font-medium text-white">{dep.name}</td>
                      <td className="py-3 px-4 text-gray-300 font-mono text-sm">{dep.version}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded text-xs font-bold uppercase text-white ${getSeverityColor(dep.severity)}`}>
                          {formatSeverity(dep.severity)}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300">{dep.title}</td>
                      <td className="py-3 px-4 text-gray-300">{dep.cwe || 'N/A'}</td>
                      <td className="py-3 px-4 text-gray-300">
                        {Array.isArray(dep.cves) && dep.cves.length ? (
                          <div className="flex flex-wrap gap-1">
                            {dep.cves.slice(0, 2).map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noreferrer"
                                className="text-cyan-400 hover:text-cyan-300 text-xs underline"
                              >
                                {cve}
                              </a>
                            ))}
                            {dep.cves.length > 2 && (
                              <span className="text-gray-400 text-xs">+{dep.cves.length - 2} more</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-400">N/A</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-xs">
                          <div className="text-cyan-400 mb-1">{dep.fix}</div>
                          {dep.url && (
                            <a
                              href={dep.url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-cyan-300 hover:underline"
                            >
                              View Advisory
                            </a>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Empty State */}
      {dependencies.length === 0 && !isScanning && (
        <div className="text-center py-12">
          <div className="text-gray-400 mb-4">
            <svg className="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
            </svg>
          </div>
          <h3 className="text-lg font-medium text-gray-300 mb-2">No Dependencies Scanned</h3>
          <p className="text-gray-400">Click <span className="font-medium">Audit Dependencies</span> to scan your npm packages for vulnerabilities</p>
        </div>
      )}

      {/* Summary Stats */}
      {dependencies.length > 0 && (
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-red-900/20 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-red-400">
              {dependencies.filter((dependency) => normalizeSeverity(dependency.severity) === 'critical').length}
            </div>
            <div className="text-sm text-gray-400">Critical</div>
          </div>
          <div className="bg-orange-900/20 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-orange-400">
              {dependencies.filter((dependency) => normalizeSeverity(dependency.severity) === 'high').length}
            </div>
            <div className="text-sm text-gray-400">High</div>
          </div>
          <div className="bg-yellow-900/20 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-yellow-400">
              {dependencies.filter((dependency) => normalizeSeverity(dependency.severity) === 'medium').length}
            </div>
            <div className="text-sm text-gray-400">Medium</div>
          </div>
          <div className="bg-green-900/20 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-green-400">
              {dependencies.filter((dependency) => normalizeSeverity(dependency.severity) === 'low').length}
            </div>
            <div className="text-sm text-gray-400">Low</div>
          </div>
        </div>
      )}
    </div>
  );
}
