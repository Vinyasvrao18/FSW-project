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

Both PhishCheck endpoints use the same nine rules and save the same score and findings. The interface uses POST /api/phishcheck/analyze. POST /api/phishcheck/check preserves the older response fields and maps the shared risk bands to SAFE, SUSPICIOUS or HIGH_RISK. Earlier history entries retain their original scores. HeaderShield accepts both targetUrl and url. Enter any public HTTP or HTTPS URL directly. HeaderShield checks the submitted URL’s own response, including redirect responses. Private and reserved network destinations are blocked.

Run npm test in the server directory and npm run build in the client directory. The HeaderShield tests mock outbound requests. To reuse a compatible database, set DB_PATH before starting the server.

## Interpreting a scan

HeaderShield evaluates six HTTP response headers. Each finding shows its possible and earned points. Missing headers earn zero, as do invalid X-Frame-Options or X-Content-Type-Options values and HSTS received over plain HTTP. Other policies receive presence checks. Even a score of 100 does not establish that a policy is sufficiently restrictive or that the site is secure. The scanner validates every resolved IP address and connects using those checked addresses, with proxying and redirects disabled.

PhishCheck examines URL text without visiting the site. Its nine rules produce a heuristic score rather than a probability. A legitimate login page may trigger rules, and a phishing page with an ordinary-looking HTTPS URL may trigger none. Both API routes use the same rules. Historical scans keep the scores recorded when they ran.
