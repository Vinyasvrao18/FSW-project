# AuthGuard-X 🛡️

A comprehensive web security suite featuring Authentication, Header Shield scanner, Phishing analysis, File Integrity hashing, and Audit History.

## 📁 Project Structure

```text
authguard-x/
  server/
    app.js            # Express app, helmet, rate limiting, session, CSRF, error handling
    db.js             # SQLite setup & schema initialization
    auth.js           # Auth routes: register, login, logout, me
    headershield.js   # HTTP security headers scanner & public destination check
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
npm ci
npm run dev
```

### 2. Client Setup
```bash
cd client
npm ci
npm run dev
```


Use Node.js 22. Run the server and client in separate terminals, then open http://localhost:5173 and register an account. SQLite creates the database at first start.

## Source versions

The account system, dashboard and weighted header checks come from FSW project.zip. The detailed header findings and extended phishing analysis come from FSW.zip. The selected-file preview and ten-record history pages are adapted from fsw1.zip.

The interface uses POST /api/phishcheck/analyze for extended analysis. Existing clients can use POST /api/phishcheck/check for the original scoring rules. HeaderShield accepts both targetUrl and url. Enter any public HTTP or HTTPS URL directly. HeaderShield checks the submitted URL’s own response, including redirect responses. Private and reserved network destinations are blocked.

Run npm test in the server directory and npm run build in the client directory. The HeaderShield tests mock outbound requests. To reuse a compatible database, set DB_PATH before starting the server.
