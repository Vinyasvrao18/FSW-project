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
    tests/            # Jest + Supertest test suites
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
npm install
npm run dev
```

### 2. Client Setup
```bash
cd client
npm install
npm run dev
```

