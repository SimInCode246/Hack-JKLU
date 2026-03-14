import { useState } from 'react';

export default function UploadRepo({ onFilesUploaded = () => {}, onFileContentUploaded, onRepoScanned = (data) => {}, onGitHubImport = () => {} }) {
  const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:5000';
  const [uploadMethod, setUploadMethod] = useState('folder');
  const [githubUrl, setGithubUrl] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [selectedFileIndex, setSelectedFileIndex] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const textFilePattern = /\.(js|cjs|mjs|jsx|ts|tsx|json|py|java|php|rb|go|rs|c|cc|cpp|h|hpp|cs|swift|kt|scala|txt|md)$/i;

  const isZipFile = (file) => file?.name?.toLowerCase().endsWith('.zip');
  const isScannableTextFile = (file) =>
    Boolean(
      file && (
        file.type.startsWith('text/') ||
        file.type.includes('json') ||
        textFilePattern.test(file.name)
      )
    );
  const isScannableFile = (file) => isScannableTextFile(file) || isZipFile(file);

  const readFile = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  };

  const scanZipFile = async (file) => {
    if (!file) return;
    setErrorMessage(null);
    setIsUploading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${API_BASE}/api/scan/repo`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.error || response.statusText || 'Zip scan request failed');
      }

      const data = await response.json();
      onRepoScanned?.(data);
      return data;
    } catch (err) {
      setErrorMessage(`Zip scan failed: ${err?.message ?? 'Unknown error'}`);
      return null;
    } finally {
      setIsUploading(false);
    }
  };

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setIsUploading(true);

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const firstScannable = files.find(isScannableFile) || null;

    // If user uploaded a zip file, scan it as a repo
    if (firstScannable && isZipFile(firstScannable)) {
      const entry = {
        file: firstScannable,
        name: firstScannable.name,
        size: firstScannable.size,
        type: firstScannable.type,
        lastModified: firstScannable.lastModified,
        content: null,
        isZip: true
      };

      setUploadedFiles([entry]);
      setSelectedFileIndex(0);
      await scanZipFile(firstScannable);
      setIsUploading(false);
      return;
    }

    const firstTextFile = files.find(isScannableTextFile) || null;
    let fileContent = null;
    try {
      if (firstTextFile) {
        fileContent = await readFile(firstTextFile);
        onFileContentUploaded?.({ name: firstTextFile.name, content: fileContent });
      }
    } catch {
      // File reading failed, continue without content
    }

    const processedFiles = await Promise.all(
      files.map(async (file) => {
        const entry = {
          file,
          name: file.name,
          size: file.size,
          type: file.type,
          lastModified: file.lastModified,
          content: null,
          isZip: isZipFile(file)
        };
        if (isScannableTextFile(file)) {
          try {
            entry.content = await readFile(file);
          } catch {
            // ignore read failures
          }
        }
        return entry;
      })
    );

    setUploadedFiles(processedFiles);
    setSelectedFileIndex(processedFiles.length ? 0 : null);
    onFilesUploaded?.(processedFiles);
    setIsUploading(false);
  };

  const handleGitHubImport = async () => {
    if (!githubUrl.trim()) return;

    setErrorMessage(null);
    setIsUploading(true);

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

      const data = await response.json();
      onRepoScanned?.(data);
      onGitHubImport?.({ url: githubUrl.trim() });
    } catch (err) {
      setErrorMessage(`GitHub import failed: ${err?.message ?? 'Unknown error'}`);
    } finally {
      setIsUploading(false);
      setGithubUrl('');
    }
  };

  const scanSelectedFile = async () => {
    if (selectedFileIndex === null) return;
    const entry = uploadedFiles[selectedFileIndex];
    if (!entry?.file) return;

    if (entry.isZip || isZipFile(entry.file)) {
      await scanZipFile(entry.file);
      return;
    }

    let content = entry.content;
    if (!content && isScannableTextFile(entry.file)) {
      try {
        content = await readFile(entry.file);
      } catch {
        // ignore
      }
    }

    if (content) {
      onFileContentUploaded?.({ name: entry.name, content });
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      const mockEvent = { target: { files } };
      handleFileUpload(mockEvent);
    }
  };

  return (
    <div className="bg-gray-800 p-6 rounded-lg">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <span className="inline-flex rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-300">
          SRC
        </span>
        Upload or Connect Code
      </h3>

      {/* Upload Method Tabs */}
      <div className="flex gap-2 mb-4">
        <button
          onClick={() => {
            setErrorMessage(null);
            setUploadMethod('folder');
          }}
          className={`px-3 py-1 rounded text-sm ${
            uploadMethod === 'folder'
              ? 'bg-cyan-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          Folder
        </button>
        <button
          onClick={() => {
            setErrorMessage(null);
            setUploadMethod('zip');
          }}
          className={`px-3 py-1 rounded text-sm ${
            uploadMethod === 'zip'
              ? 'bg-cyan-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          ZIP File
        </button>
        <button
          onClick={() => {
            setErrorMessage(null);
            setUploadMethod('github');
          }}
          className={`px-3 py-1 rounded text-sm ${
            uploadMethod === 'github'
              ? 'bg-cyan-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          GitHub
        </button>
      </div>

      {errorMessage && (
        <div className="mb-4 rounded border border-red-600 bg-red-900/40 p-3 text-sm text-red-200">
          {errorMessage}
        </div>
      )}

      {/* Upload Interface */}
      {uploadMethod === 'folder' && (
        <div
          className="border-2 border-dashed border-gray-600 rounded-lg p-8 text-center hover:border-cyan-500 transition-colors"
          onDragOver={handleDragOver}
          onDrop={handleDrop}
        >
          <div className="text-gray-400 mb-4">
            <svg className="w-12 h-12 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5a2 2 0 012-2h4a2 2 0 012 2v2H8V5z" />
            </svg>
            <p className="text-lg font-medium">Drop your project folder here</p>
            <p className="text-sm">or click to browse folders</p>
          </div>

          <input
            type="file"
            multiple
            webkitdirectory=""
            className="hidden"
            id="folder-upload"
            onChange={handleFileUpload}
          />

          <label
            htmlFor="folder-upload"
            className="inline-block px-6 py-3 bg-cyan-600 hover:bg-cyan-500 rounded-lg cursor-pointer transition-colors disabled:opacity-50"
          >
            {isUploading ? 'Uploading...' : 'Choose Folder'}
          </label>
        </div>
      )}

      {uploadMethod === 'zip' && (
        <div
          className="border-2 border-dashed border-gray-600 rounded-lg p-8 text-center hover:border-cyan-500 transition-colors"
          onDragOver={handleDragOver}
          onDrop={handleDrop}
        >
          <div className="text-gray-400 mb-4">
            <svg className="w-12 h-12 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
            </svg>
            <p className="text-lg font-medium">Drop your ZIP file here</p>
            <p className="text-sm">or click to browse ZIP files</p>
          </div>

          <input
            type="file"
            accept=".zip,.rar,.7z"
            className="hidden"
            id="zip-upload"
            onChange={handleFileUpload}
          />

          <label
            htmlFor="zip-upload"
            className="inline-block px-6 py-3 bg-cyan-600 hover:bg-cyan-500 rounded-lg cursor-pointer transition-colors disabled:opacity-50"
          >
            {isUploading ? 'Uploading...' : 'Choose ZIP File'}
          </label>
        </div>
      )}

      {uploadMethod === 'github' && (
        <div className="space-y-4">
          <div className="bg-gray-700 p-4 rounded-lg">
            <h4 className="font-medium mb-2">Connect GitHub Repository</h4>
            <p className="text-sm text-gray-400 mb-4">
              Enter the GitHub repository URL to scan the codebase
            </p>

            <div className="flex gap-2">
              <input
                type="text"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/username/repository"
                className="flex-1 px-3 py-2 bg-gray-600 border border-gray-500 rounded text-white placeholder-gray-400"
              />
              <button
                onClick={handleGitHubImport}
                disabled={!githubUrl.trim() || isUploading}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 rounded flex items-center gap-2"
              >
                {isUploading ? 'Connecting...' : 'Connect Repo'}
              </button>
            </div>

            {errorMessage && (
              <div className="mt-3 rounded border border-red-600 bg-red-900/40 p-3 text-sm text-red-200">
                {errorMessage}
              </div>
            )}
          </div>

          <div className="text-sm text-gray-400">
            <p>Supported: Public repositories</p>
            <p>Private repositories require authentication (coming soon)</p>
          </div>
        </div>
      )}

      {uploadedFiles.length > 0 && (
        <div className="mt-6 bg-gray-900 p-4 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between mb-3">
            <div className="text-sm font-semibold text-white">Uploaded files</div>
            <button
              onClick={scanSelectedFile}
              disabled={selectedFileIndex === null || isUploading}
              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded text-sm"
            >
              Scan Selected
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            {uploadedFiles.map((file, idx) => (
              <button
                key={file.name + idx}
                onClick={() => setSelectedFileIndex(idx)}
                className={`px-3 py-2 rounded text-sm text-left border ${
                  selectedFileIndex === idx ? 'border-cyan-400 bg-cyan-500/10' : 'border-gray-700 bg-gray-800'
                }`}
              >
                <div className="font-medium text-white">{file.name}</div>
                <div className="text-xs text-gray-400">
                  {file.size ? `${Math.round(file.size / 1024)} KB` : 'unknown size'}
                    {file.content || file.isZip ? ' · ready to scan' : ' · not readable'}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="mt-4 text-sm text-gray-400">
        <p>Supported formats: JS, TS, Python, Java, PHP, Ruby, Go, Rust, C/C++, C#, VB, Swift, Kotlin, Scala</p>
      </div>
    </div>
  );
}
