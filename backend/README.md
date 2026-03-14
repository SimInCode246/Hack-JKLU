# Security Scanner Backend

A Node.js Express API server for the Security Scanner Dashboard with support for multiple programming languages and package ecosystems.

## Features

- **Code vulnerability scanning** with expanded patterns for:
  - SSRF (Server-Side Request Forgery)
  - Insecure deserialization
  - Hardcoded secrets
  - SQL injection
  - Path traversal
  - Weak cryptography
  - Insecure random number generation
  - Missing security headers
  - And more...

- **Multi-ecosystem dependency analysis**:
  - npm (Node.js)
  - pip (Python) - requires `pip-audit`
  - bundler (Ruby) - requires `bundler-audit`
  - Support for requirements.txt, Pipfile, pyproject.toml, Gemfile, etc.

- Dashboard statistics
- File upload support for various formats
- Repository scanning with ZIP upload

## Installation

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. (Optional) Install additional tools for enhanced scanning:
   ```bash
   # For Python dependency scanning
   pip install pip-audit
   
   # For Ruby dependency scanning
   gem install bundler-audit
   ```

## Running the Server

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

The server will run on `http://localhost:5000` by default.

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/scan/code` - Scan code for vulnerabilities (uses ESLint + custom security patterns)
- `POST /api/scan/dependencies` - Scan dependencies for multiple ecosystems
  - Supports: package.json, requirements.txt, Pipfile, pyproject.toml, Gemfile, composer.json
  - Accepts text content, file upload, or ZIP archive
- `POST /api/scan/repo` - Scan entire repository (ZIP) for code and dependency vulnerabilities
- `POST /api/scan/github` - Scan a public GitHub repo by URL (downloads ZIP and scans)
- `GET /api/dashboard/stats` - Get dashboard statistics

## Supported File Types

### Code Scanning
- JavaScript (.js)
- TypeScript (.ts)
- JSX (.jsx)
- TSX (.tsx)

### Dependency Scanning
- **npm**: package.json
- **Python**: requirements.txt, Pipfile, pyproject.toml, poetry.lock
- **Ruby**: Gemfile, Gemfile.lock
- **PHP**: composer.json
- **Java**: pom.xml (planned)
- **.NET**: packages.config, .csproj (planned)

## Technologies Used

- Express.js
- Multer (file uploads)
- CORS