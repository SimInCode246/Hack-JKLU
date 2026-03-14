import { useEffect, useState } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import { FaDownload } from 'react-icons/fa';

export default function Dashboard({ vulnerabilities = [], dependencies = [] }) {
  const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:5000';
  const normalizeSeverity = (severity = '') => severity.toLowerCase();

  const [stats, setStats] = useState(null);
  const [statsError, setStatsError] = useState(null);
  const [filteredSeverity, setFilteredSeverity] = useState(null);

  const handlePieClick = (data) => {
    if (data && data.name) {
      setFilteredSeverity(filteredSeverity === data.name.toLowerCase() ? null : data.name.toLowerCase());
    }
  };

  const getFilteredItems = () => {
    if (!filteredSeverity) return [...vulnerabilities, ...dependencies];
    return [...vulnerabilities, ...dependencies].filter(item =>
      normalizeSeverity(item.severity) === filteredSeverity
    );
  };

  const filteredItems = getFilteredItems();

  const calculateSeverityCounts = () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    [...vulnerabilities, ...dependencies].forEach((item) => {
      const sev = normalizeSeverity(item.severity);
      if (counts[sev] !== undefined) counts[sev] += 1;
    });
    return counts;
  };

  const severityCounts = calculateSeverityCounts();

  useEffect(() => {
    let canceled = false;
    setStatsError(null);

    fetch(`${API_BASE}/api/dashboard/stats`, { cache: 'no-store' })
      .then((res) => res.json())
      .then((data) => {
        if (!canceled) {
          setStats(data);
        }
      })
      .catch((err) => {
        if (!canceled) {
          setStatsError(err.message || 'Failed to load dashboard stats');
        }
      })
      .finally(() => {
        // loading state not currently displayed
      });

    return () => {
      canceled = true;
    };
  }, [API_BASE]);

  const trendData = stats?.trend?.length
    ? stats.trend.map((item) => ({
        day: item.date,
        vulnerabilities: item.vulnerabilities,
        dependencies: dependencies.length
      }))
    : [
        { day: 'Mon', vulnerabilities: 12, dependencies: dependencies.length > 0 ? dependencies.length : 3 },
        { day: 'Tue', vulnerabilities: 19, dependencies: dependencies.length > 0 ? dependencies.length + 2 : 5 },
        { day: 'Wed', vulnerabilities: 15, dependencies: dependencies.length > 0 ? Math.max(0, dependencies.length - 1) : 2 },
        { day: 'Thu', vulnerabilities: 8, dependencies: dependencies.length > 0 ? dependencies.length + 1 : 4 },
        { day: 'Fri', vulnerabilities: 12, dependencies: dependencies.length > 0 ? dependencies.length + 3 : 6 },
        { day: 'Sat', vulnerabilities: 6, dependencies: dependencies.length > 0 ? Math.max(1, dependencies.length - 2) : 1 },
        { day: 'Sun', vulnerabilities: 9, dependencies: dependencies.length > 0 ? dependencies.length : 3 }
      ];

  const severityData = stats?.severityBreakdown
    ? [
        { name: 'Critical', value: stats.severityBreakdown.critical || 0, color: '#ef4444' },
        { name: 'High', value: stats.severityBreakdown.high || 0, color: '#f97316' },
        { name: 'Medium', value: stats.severityBreakdown.medium || 0, color: '#eab308' },
        { name: 'Low', value: stats.severityBreakdown.low || 0, color: '#22c55e' }
      ]
    : [
        { name: 'Critical', value: severityCounts.critical, color: '#ef4444' },
        { name: 'High', value: severityCounts.high, color: '#f97316' },
        { name: 'Medium', value: severityCounts.medium, color: '#eab308' },
        { name: 'Low', value: severityCounts.low, color: '#22c55e' }
      ];

  const categoriesData = [
    { name: 'Injection', issues: 18 },
    { name: 'XSS', issues: 24 },
    { name: 'Auth', issues: 12 },
    { name: 'Config', issues: 8 },
    { name: 'Crypto', issues: 6 }
  ];

  const fixRateData = [
    { week: 'Week 1', fixed: 45 },
    { week: 'Week 2', fixed: 62 },
    { week: 'Week 3', fixed: 78 },
    { week: 'Week 4', fixed: 89 }
  ];

  const totalVulns = stats?.vulnerabilitiesFound ?? (vulnerabilities.length + dependencies.length);
  const avgRisk = stats?.averageRiskScore ?? (totalVulns > 0 ? Math.round(vulnerabilities.reduce((acc, vulnerability) => {
    const severity = normalizeSeverity(vulnerability.severity);
    if (severity === 'critical') return acc + 30;
    if (severity === 'high') return acc + 20;
    if (severity === 'medium') return acc + 10;
    return acc + 5;
  }, 0) / totalVulns) : 0);

  const resolvedIssues = stats?.resolvedIssues ?? Math.floor(totalVulns * 0.7);
  const scansToday = stats?.scansToday ?? 3;

  const handleExport = async (format) => {
    try {
      const response = await fetch(`${API_BASE}/api/export/dashboard/${format}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dashboard.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        alert('Error exporting dashboard data');
      }
    } catch (error) {
      console.error('Error exporting dashboard:', error);
      alert('Error exporting dashboard data');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
            Security Dashboard
          </h1>
          <div className="px-3 py-1 bg-cyan-900/20 rounded-full text-cyan-400 text-sm">
            Live Data
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport('csv')}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            <FaDownload />
            CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
          >
            <FaDownload />
            JSON
          </button>
        </div>
      </div>

      {statsError && (
        <div className="bg-red-900/20 border border-red-500 p-4 rounded-lg mb-6">
          <div className="text-red-200 font-semibold">Unable to load dashboard stats</div>
          <div className="text-red-300 text-sm">{statsError}</div>
        </div>
      )}

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-700 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <div className="rounded-full bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">TV</div>
            <div className="text-right">
              <div className="text-2xl font-bold text-cyan-400">{totalVulns}</div>
              <div className="text-sm text-gray-400">Total Vulnerabilities</div>
            </div>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-cyan-500 h-2 rounded-full"
              style={{ width: `${Math.min(totalVulns * 10, 100)}%` }}
            />
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-700 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <div className="rounded-full bg-purple-500/10 px-3 py-1 text-xs font-semibold text-purple-300">RSK</div>
            <div className="text-right">
              <div className="text-2xl font-bold text-purple-400">{avgRisk}</div>
              <div className="text-sm text-gray-400">Avg Risk Score</div>
            </div>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-purple-500 h-2 rounded-full"
              style={{ width: `${avgRisk}%` }}
            />
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-700 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <div className="rounded-full bg-green-500/10 px-3 py-1 text-xs font-semibold text-green-300">FIX</div>
            <div className="text-right">
              <div className="text-2xl font-bold text-green-400">{resolvedIssues}</div>
              <div className="text-sm text-gray-400">Issues Resolved</div>
            </div>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-green-500 h-2 rounded-full"
              style={{ width: `${totalVulns > 0 ? (resolvedIssues / totalVulns) * 100 : 0}%` }}
            />
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg hover:bg-gray-700 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <div className="rounded-full bg-pink-500/10 px-3 py-1 text-xs font-semibold text-pink-300">SCAN</div>
            <div className="text-right">
              <div className="text-2xl font-bold text-pink-400">{scansToday}</div>
              <div className="text-sm text-gray-400">Scans Today</div>
            </div>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div className="bg-pink-500 h-2 rounded-full" style={{ width: '60%' }} />
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Trend */}
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <span className="inline-flex rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-300">TR</span>
            Vulnerability Trend
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="day" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    color: '#F9FAFB'
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="vulnerabilities"
                  stroke="#06B6D4"
                  strokeWidth={2}
                  dot={{ fill: '#06B6D4', strokeWidth: 2, r: 4 }}
                  name="Code Issues"
                />
                <Line
                  type="monotone"
                  dataKey="dependencies"
                  stroke="#8B5CF6"
                  strokeWidth={2}
                  dot={{ fill: '#8B5CF6', strokeWidth: 2, r: 4 }}
                  name="Dependency Issues"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-gray-800 p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-semibold flex items-center gap-2">
              <span className="inline-flex rounded-full bg-orange-500/10 px-2 py-1 text-xs font-semibold text-orange-300">SEV</span>
              Severity Distribution
              {filteredSeverity && (
                <span className="text-sm text-orange-400">
                  (Filtered: {filteredSeverity.charAt(0).toUpperCase() + filteredSeverity.slice(1)})
                </span>
              )}
            </h3>
            {filteredSeverity && (
              <button
                onClick={() => setFilteredSeverity(null)}
                className="text-sm text-gray-400 hover:text-white"
              >
                Clear Filter
              </button>
            )}
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, percent = 0 }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  onClick={handlePieClick}
                  style={{ cursor: 'pointer' }}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <p className="text-sm text-gray-400 mt-2 text-center">
            Click on a slice to filter vulnerabilities
          </p>
        </div>

        {/* Vulnerability Categories */}
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <span className="inline-flex rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-300">CAT</span>
            Vulnerability Categories
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoriesData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="name" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    color: '#F9FAFB'
                  }}
                />
                <Bar dataKey="issues" fill="#06B6D4" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Fix Rate Over Time */}
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <span className="inline-flex rounded-full bg-green-500/10 px-2 py-1 text-xs font-semibold text-green-300">FIX</span>
            Fix Rate Over Time
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={fixRateData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="week" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    color: '#F9FAFB'
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="fixed"
                  stroke="#10B981"
                  strokeWidth={3}
                  dot={{ fill: '#10B981', strokeWidth: 2, r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Filtered Vulnerabilities Table */}
      {filteredSeverity && (
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <span className="inline-flex rounded-full bg-orange-500/10 px-2 py-1 text-xs font-semibold text-orange-300">FLT</span>
            Filtered Vulnerabilities ({filteredSeverity.charAt(0).toUpperCase() + filteredSeverity.slice(1)})
          </h3>
          {filteredItems.length === 0 ? (
            <p className="text-gray-400 text-center py-8">No vulnerabilities found for this severity level.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Title</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Description</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Type</th>
                    <th className="text-left py-3 px-4 text-gray-300 font-semibold">Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredItems.slice(0, 10).map((item, idx) => (
                    <tr key={idx} className="border-b border-gray-700 hover:bg-gray-700/50">
                      <td className="py-3 px-4 font-medium text-white">{item.title || item.name}</td>
                      <td className="py-3 px-4 text-gray-300 max-w-xs truncate">{item.description}</td>
                      <td className="py-3 px-4 text-gray-300">
                        {item.name ? 'Dependency' : 'Code Issue'}
                      </td>
                      <td className="py-3 px-4 text-gray-300 max-w-xs truncate">{item.fix || 'No fix available'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredItems.length > 10 && (
                <p className="text-sm text-gray-400 mt-2">
                  Showing first 10 of {filteredItems.length} vulnerabilities
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Top Vulnerable Packages */}
      {stats?.topPackages?.length > 0 && (
        <div className="bg-gray-800 p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <span className="inline-flex rounded-full bg-purple-500/10 px-2 py-1 text-xs font-semibold text-purple-300">TOP</span>
            Top Vulnerable Packages
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-gray-300 font-semibold">Package</th>
                  <th className="text-left py-3 px-4 text-gray-300 font-semibold">Occurrences</th>
                  <th className="text-left py-3 px-4 text-gray-300 font-semibold">Worst Severity</th>
                </tr>
              </thead>
              <tbody>
                {stats.topPackages.map((pkg, idx) => (
                  <tr key={idx} className="border-b border-gray-700 hover:bg-gray-700/50">
                    <td className="py-3 px-4 font-medium text-white">{pkg.name}</td>
                    <td className="py-3 px-4 text-gray-300">{pkg.count}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded text-xs font-bold uppercase text-white ${
                        pkg.highestSeverity === 'critical' ? 'bg-red-600' :
                        pkg.highestSeverity === 'high' ? 'bg-orange-600' :
                        pkg.highestSeverity === 'medium' ? 'bg-yellow-600' : 'bg-green-600'
                      }`}>
                        {pkg.highestSeverity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent Activity */}
      <div className="bg-gray-800 p-6 rounded-lg">
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <span className="inline-flex rounded-full bg-purple-500/10 px-2 py-1 text-xs font-semibold text-purple-300">LOG</span>
          Recent Activity
        </h3>
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 bg-gray-700/50 rounded-lg">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <div className="flex-1">
              <p className="text-sm font-medium">Security scan completed</p>
              <p className="text-xs text-gray-400">2 minutes ago</p>
            </div>
            <span className="text-xs px-2 py-1 bg-green-900/20 text-green-400 rounded">SUCCESS</span>
          </div>

          <div className="flex items-center gap-3 p-3 bg-gray-700/50 rounded-lg">
            <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
            <div className="flex-1">
              <p className="text-sm font-medium">Dependency audit completed</p>
              <p className="text-xs text-gray-400">5 minutes ago</p>
            </div>
            <span className="text-xs px-2 py-1 bg-cyan-900/20 text-cyan-400 rounded">ISSUES FOUND</span>
          </div>

          <div className="flex items-center gap-3 p-3 bg-gray-700/50 rounded-lg">
            <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
            <div className="flex-1">
              <p className="text-sm font-medium">GitHub repository connected</p>
              <p className="text-xs text-gray-400">10 minutes ago</p>
            </div>
            <span className="text-xs px-2 py-1 bg-purple-900/20 text-purple-400 rounded">CONNECTED</span>
          </div>
        </div>
      </div>
    </div>
  );
}
