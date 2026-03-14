import React, { useState, useEffect } from 'react';
import { FaHistory, FaTrash, FaDownload } from 'react-icons/fa';

const History = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/history');
      const data = await response.json();
      setHistory(data);
    } catch (error) {
      console.error('Error fetching history:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (scanId) => {
    if (!confirm('Are you sure you want to delete this scan from history?')) return;

    try {
      const response = await fetch(`http://localhost:3001/api/history/${scanId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        fetchHistory(); // Refresh history
      } else {
        alert('Error deleting scan');
      }
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Error deleting scan');
    }
  };

  const handleExport = async (scanId, format) => {
    try {
      const response = await fetch(`http://localhost:3001/api/export/${scanId}/${format}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${scanId}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        alert('Error exporting scan');
      }
    } catch (error) {
      console.error('Error exporting scan:', error);
      alert('Error exporting scan');
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="flex items-center mb-6">
        <FaHistory className="text-2xl text-blue-600 mr-3" />
        <h1 className="text-3xl font-bold text-gray-800">Scan History</h1>
      </div>

      {history.length === 0 ? (
        <div className="text-center py-12">
          <FaHistory className="text-6xl text-gray-300 mx-auto mb-4" />
          <p className="text-gray-500 text-lg">No scan history available</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {history.map((scan) => (
            <div key={scan.id} className="bg-white rounded-lg shadow-md p-6 border border-gray-200">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-800">
                    {scan.filename || 'Repository Scan'}
                  </h3>
                  <p className="text-sm text-gray-500">
                    {formatDate(scan.timestamp)}
                  </p>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleExport(scan.id, 'csv')}
                    className="flex items-center px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                  >
                    <FaDownload className="mr-1" />
                    CSV
                  </button>
                  <button
                    onClick={() => handleExport(scan.id, 'json')}
                    className="flex items-center px-3 py-1 bg-purple-500 text-white rounded hover:bg-purple-600"
                  >
                    <FaDownload className="mr-1" />
                    JSON
                  </button>
                  <button
                    onClick={() => handleDelete(scan.id)}
                    className="flex items-center px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600"
                  >
                    <FaTrash className="mr-1" />
                    Delete
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">{scan.stats?.critical || 0}</div>
                  <div className="text-sm text-gray-500">Critical</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">{scan.stats?.high || 0}</div>
                  <div className="text-sm text-gray-500">High</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-600">{scan.stats?.medium || 0}</div>
                  <div className="text-sm text-gray-500">Medium</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">{scan.stats?.low || 0}</div>
                  <div className="text-sm text-gray-500">Low</div>
                </div>
              </div>

              <div className="text-sm text-gray-600">
                <span className="font-medium">Total Vulnerabilities:</span> {scan.stats?.total || 0} |
                <span className="font-medium ml-2">Dependencies:</span> {scan.stats?.dependencies || 0} |
                <span className="font-medium ml-2">Code Issues:</span> {scan.stats?.code || 0}
              </div>

              {selectedScan === scan.id && (
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <h4 className="font-semibold mb-2">Scan Details</h4>
                  <div className="bg-gray-50 p-4 rounded text-sm">
                    <pre className="whitespace-pre-wrap">{JSON.stringify(scan, null, 2)}</pre>
                  </div>
                </div>
              )}

              <button
                onClick={() => setSelectedScan(selectedScan === scan.id ? null : scan.id)}
                className="mt-2 text-blue-600 hover:text-blue-800 text-sm"
              >
                {selectedScan === scan.id ? 'Hide Details' : 'Show Details'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default History;