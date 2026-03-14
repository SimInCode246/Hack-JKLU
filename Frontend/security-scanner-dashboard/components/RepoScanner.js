import { useMemo, useState } from 'react';

export default function RepoScanner({ onRepoScanned }) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [githubUrl, setGithubUrl] = useState('');
  const [results, setResults] = useState(null);
  const [codeSeverityFilter, setCodeSeverityFilter] = useState('all');
  const [depSeverityFilter, setDepSeverityFilter] = useState('all');
  const [errorMessage, setErrorMessage] = useState(null);
  const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:5000';

  const normalizeSeverity = (severity = '') => severity.toLowerCase();

  const formatSeverity = (severity = '') => {
    const normalized = normalizeSeverity(severity);
    return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : 'Unknown';
  };

  const normalizeRepoResults = (data) => ({
    ...data,
    codeScan: data?.codeScan
      ? {
          ...data.codeScan,
          vulnerabilities: (data.codeScan.vulnerabilities || []).map((item) => ({
            ...item,
            severity: normalizeSeverity(item?.severity)
          }))
        }
      : null,
    dependencyScan: data?.dependencyScan
      ? {
          ...data.dependencyScan,
          dependencies: (data.dependencyScan.dependencies || []).map((item) => ({
            ...item,
            severity: normalizeSeverity(item?.severity)
          }))
        }
      : null
  });

  const runRepoScan = async () => {
    if (!githubUrl.trim()) return;

    setIsScanning(true);
    setScanProgress(0);
    setResults(null);
    setErrorMessage(null);

    // Simulate scanning progress
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        const newProgress = prev + Math.random() * 8;
        return newProgress > 90 ? 90 : newProgress;
      });
    }, 300);

    try {
      const response = await fetch(`${API_BASE}/api/scan/github`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: githubUrl.trim() })
      });

      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        throw new Error(errorPayload.error || response.statusText || 'GitHub scan request failed');
      }

      const data = normalizeRepoResults(await response.json());
      setResults(data);
      onRepoScanned?.(data);
    } catch (error) {
      setErrorMessage(`GitHub scan failed: ${error?.message ?? 'Unknown error'}`);
      setResults({ error: error.message });
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

  const filteredCodeVulnerabilities = useMemo(() => {
    const vulns = results?.codeScan?.vulnerabilities || [];
    if (codeSeverityFilter === 'all') return vulns;
    return vulns.filter((v) => normalizeSeverity(v.severity) === codeSeverityFilter);
  }, [results, codeSeverityFilter]);

  const filteredDependencyVulnerabilities = useMemo(() => {
    const deps = results?.dependencyScan?.dependencies || [];
    if (depSeverityFilter === 'all') return deps;
    return deps.filter((d) => normalizeSeverity(d.severity) === depSeverityFilter);
  }, [results, depSeverityFilter]);

  return (
    <div className="bg-gray-800 p-6 rounded-lg">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <span className="inline-flex rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-300">
              REP
            </span>
            Connect GitHub Repository
          </h2>
          <p className="text-sm mt-1 text-gray-400">
            Enter the GitHub repository URL to scan the codebase
          </p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <div className="flex gap-2">
            <input
              type="text"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/username/repository"
              className="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-400 min-w-80"
            />
            <button
              onClick={runRepoScan}
              disabled={isScanning || !githubUrl.trim()}
              className="px-6 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg flex items-center gap-2 transition-colors"
            >
              <span className="rounded bg-cyan-500/20 px-2 py-0.5 text-[10px] font-semibold">SCAN</span>
              {isScanning ? 'Scanning...' : 'Scan Repository'}
            </button>
          </div>
        </div>
      </div>

      {errorMessage && (
        <div className="mb-4 rounded border border-red-600 bg-red-900/40 p-3 text-sm text-red-200">
          {errorMessage}
        </div>
      )}

      {/* Progress Bar */}
      {isScanning && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-400">Scanning repository...</span>
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

      {/* Results */}
      {results && !results.error && (
        <div className="space-y-6">
          {/* Overall Risk Score */}
          <div className="bg-gray-700 p-4 rounded-lg">
            <h3 className="text-lg font-semibold mb-2">Overall Risk Assessment</h3>
            <div className="flex items-center gap-4">
              <div className="text-2xl font-bold text-cyan-400">
                Risk Score: {results.overallRiskScore}/100
              </div>
              <div className="text-sm text-gray-400">
                Based on code and dependency vulnerabilities
              </div>
            </div>
          </div>

          {/* Code Scan Results */}
          {results.codeScan && (
            <div>
              <h3 className="text-lg font-semibold mb-4">Code Vulnerabilities</h3>
              <div className="bg-gray-700 p-4 rounded-lg mb-4">
                <div className="flex items-center gap-4 mb-2">
                  <span className="text-cyan-400">Files Scanned: {results.codeScan.filesScanned}</span>
                  <span className="text-cyan-400">Risk Score: {results.codeScan.riskScore}/100</span>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div className="text-sm text-gray-300">
                  Showing {filteredCodeVulnerabilities.length} of {results.codeScan.vulnerabilities.length} findings
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-400">Filter:</span>
                  <select
                    value={codeSeverityFilter}
                    onChange={(e) => setCodeSeverityFilter(e.target.value)}
                    className="bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white"
                  >
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {filteredCodeVulnerabilities.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">File</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Rule</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Issue</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Severity</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Line</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Info</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Fix</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCodeVulnerabilities.slice(0, 50).map((vulnerability, index) => (
                        <tr key={index} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="py-3 px-4 text-gray-300 font-mono text-sm">{vulnerability.file}</td>
                          <td className="py-3 px-4 text-gray-300">
                            {vulnerability.ruleId ? (
                              <a
                                href={vulnerability.docsUrl ?? '#'}
                                target="_blank"
                                rel="noreferrer"
                                className="text-cyan-300 hover:underline"
                              >
                                {vulnerability.ruleId}
                              </a>
                            ) : (
                              <span className="text-gray-300">N/A</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-gray-300">{vulnerability.description || vulnerability.title}</td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-1 rounded text-xs font-bold uppercase text-white ${getSeverityColor(vulnerability.severity)}`}>
                              {formatSeverity(vulnerability.severity)}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-gray-300">{vulnerability.line || 'N/A'}</td>
                          <td className="py-3 px-4">
                            {vulnerability.docsUrl ? (
                              <a
                                href={vulnerability.docsUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-cyan-400 hover:text-cyan-300 text-sm underline"
                              >
                                Docs
                              </a>
                            ) : (
                              <span className="text-gray-400 text-sm">-</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-gray-300">
                            {vulnerability.fix ? (
                              <details className="cursor-pointer">
                                <summary className="text-cyan-400 hover:underline text-sm">View fix</summary>
                                <pre className="mt-2 p-2 bg-gray-900 rounded text-xs overflow-x-auto">
                                  {vulnerability.fix}
                                </pre>
                              </details>
                            ) : (
                              <span className="text-gray-400 text-sm">-</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-gray-400 text-center py-8">No code vulnerabilities detected for the selected severity.</p>
              )}
            </div>
          )}

          {/* Dependency Scan Results */}
          {results.dependencyScan && (
            <div>
              <h3 className="text-lg font-semibold mb-4">Dependency Vulnerabilities</h3>
              <div className="bg-gray-700 p-4 rounded-lg mb-4">
                <div className="flex items-center gap-4 mb-2">
                  <span className="text-cyan-400">Total Dependencies: {results.dependencyScan.totalDependencies}</span>
                  <span className="text-cyan-400">Vulnerable: {results.dependencyScan.vulnerableCount}</span>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                <div className="text-sm text-gray-300">
                  Showing {filteredDependencyVulnerabilities.length} of {results.dependencyScan.dependencies.length} findings
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-400">Filter:</span>
                  <select
                    value={depSeverityFilter}
                    onChange={(e) => setDepSeverityFilter(e.target.value)}
                    className="bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white"
                  >
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {filteredDependencyVulnerabilities.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Package</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Vulnerable Versions</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Severity</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Vulnerability</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">CWE</th>
                        <th className="text-left py-3 px-4 text-gray-300 font-semibold">Fix</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDependencyVulnerabilities.map((dependency, index) => (
                        <tr key={index} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="py-3 px-4 font-medium text-white">{dependency.name}</td>
                          <td className="py-3 px-4 text-gray-300 font-mono text-sm">{dependency.version}</td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-1 rounded text-xs font-bold uppercase text-white ${getSeverityColor(dependency.severity)}`}>
                              {formatSeverity(dependency.severity)}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-gray-300">{dependency.title}</td>
                          <td className="py-3 px-4 text-gray-300">{dependency.cwe || 'N/A'}</td>
                          <td className="py-3 px-4">
                            <div className="text-xs">
                              <div className="text-cyan-400 mb-1">{dependency.fix}</div>
                              {dependency.url && (
                                <a
                                  href={dependency.url}
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
              ) : (
                <p className="text-gray-400 text-center py-8">No dependency vulnerabilities detected for the selected severity.</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Error State */}
      {results?.error && (
        <div className="bg-red-900/20 border border-red-500 p-4 rounded-lg">
          <h3 className="text-red-400 font-semibold mb-2">Scan Failed</h3>
          <p className="text-red-300">{results.error}</p>
        </div>
      )}
    </div>
  );
}
