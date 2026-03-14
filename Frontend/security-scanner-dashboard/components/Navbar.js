export default function Navbar({ currentPage, setCurrentPage }) {
  const navItems = [
    { id: 'scanner', label: 'Scanner', icon: 'SCN' },
    { id: 'dashboard', label: 'Dashboard', icon: 'DB' },
    { id: 'dependencies', label: 'Dependencies', icon: 'PKG' },
    { id: 'repo', label: 'Connect GitHub Repository', icon: 'REP' },
    { id: 'history', label: 'History', icon: 'HIS' }
  ];

  return (
    <header className="bg-gray-800 border-b border-gray-700 px-4 py-4">
      <div className="container mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-r from-cyan-500 to-purple-500 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold">S</span>
          </div>
          <div>
            <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              SecureScope
            </h1>
            <p className="text-xs text-gray-400">Security Vulnerability Scanner</p>
          </div>
        </div>

        <nav className="flex items-center gap-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`px-4 py-2 rounded-lg flex items-center gap-2 transition-all ${
                currentPage === item.id
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-300 hover:bg-gray-700'
              }`}
            >
              <span className="rounded-full bg-black/20 px-2 py-0.5 text-[10px] font-semibold tracking-wide">
                {item.icon}
              </span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-2 px-3 py-2 bg-cyan-900/20 rounded-lg border border-cyan-500/30">
          <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
          <span className="text-sm text-cyan-400">AI Engine Active</span>
        </div>
      </div>
    </header>
  );
}
