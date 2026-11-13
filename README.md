# AuthGuard-X 🛡️

A comprehensive web security suite featuring Authentication, Header Shield scanner, Phishing analysis, File Integrity hashing, and Audit History.

## 📁 Project Structure

```text
authguard-x/
  server/
    app.js            # Express app, helmet, rate limiting, session, CSRF, error handling
    db.js             # SQLite setup & schema initialization
    auth.js           # Auth routes: register, login, logout, me
    headershield.js   # HTTP security headers scanner & allowlist check
    phishcheck.js     # Heuristic phishing & URL risk scoring
    fileintegrity.js  # File upload, SHA-256 hash calculation, comparison & logging
    history.js        # Audit trail logs & dashboard summary metrics
    helpers.js        # Standardized ok()/fail() responses & validation helpers
  client/src/
    api.js            # Unified fetch wrapper with auto-CSRF header injection
    pages/            # Login, Register, Dashboard, HeaderShield, PhishCheck, FileIntegrity, History
    components/       # Layout, StatusBadge, ResultTable, EmptyState, Alert
  .env.example
  README.md
```

## 🚀 Quick Start

### 1. Server Setup
```bash
cd server
npm ci
npm run db:init
npm run dev
```

### 2. Client Setup
```bash
cd client
npm ci
npm run dev
```


Use Node.js 22. Run the server and client in separate terminals, then open http://localhost:5173 and register an account. The database setup command creates server/authguard.db from server/schema.sql. Startup also runs this setup automatically. Running it again preserves existing accounts, scans and file fingerprints. The server prints the active database path.

## Source versions

The account system, dashboard and weighted header checks come from FSW project.zip. The detailed header findings and extended phishing analysis come from FSW.zip. The selected-file preview and ten-record history pages are adapted from fsw1.zip.

The interface uses POST /api/phishcheck/analyze for extended analysis. Existing clients can use POST /api/phishcheck/check for the original scoring rules. HeaderShield accepts both targetUrl and url. Its allowlist defaults to example.com. Set ALLOWED_SCAN_HOSTS in the server environment for additional approved hostnames.

Run npm run build in the client directory to create the production frontend. To reuse a compatible database, set DB_PATH before starting the server.
