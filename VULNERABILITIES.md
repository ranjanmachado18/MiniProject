# VulnBank — Vulnerability Catalogue

Each row is a real, working bug in this codebase, placed intentionally.
Use this as your ground-truth list to score scanner results against.

| # | Vulnerability | CWE | OWASP Top 10 (2021) | Location | How to trigger |
|---|---|---|---|---|---|
| 1 | SQL Injection in login | CWE-89 | A03 Injection | `backend/routes/auth.js` `POST /api/auth/login` | `{"username":"admin' --","password":"x"}` |
| 2 | SQL Injection in account search | CWE-89 | A03 Injection | `backend/routes/accounts.js` `GET /api/accounts?owner=` | `?owner=x' UNION SELECT 1,1,'hax',999999--` |
| 3 | SQL Injection in user search | CWE-89 | A03 Injection | `backend/routes/users.js` `GET /api/users/search?q=` | `?q=' OR '1'='1` |
| 4 | Plaintext password storage | CWE-256 | A02 Crypto Failures | `backend/db/db.js`, `routes/auth.js` | `GET /api/users` returns raw `password` column |
| 5 | Hard-coded weak JWT secret | CWE-798 | A02 Crypto Failures | `backend/middleware/auth.js` (`secret123`) | Forge tokens offline with the known secret |
| 6 | Unverified-signature fallback (`jwt.decode` on verify failure) | CWE-347 | A02/A07 | `middleware/auth.js verifyToken` | Send a token signed with a wrong key / `alg:none`; payload is still trusted |
| 7 | Broken Function Level Authorization | CWE-285 | A01 Broken Access Control | `routes/admin.js`, `routes/users.js GET /` | Any token with `role` claim tampered to `admin` reaches admin routes |
| 8 | IDOR on account lookup | CWE-639 | A01 Broken Access Control | `routes/accounts.js GET /:id` | Log in as bob, request account id belonging to alice |
| 9 | IDOR on transaction history | CWE-639 | A01 Broken Access Control | `routes/transactions.js GET /account/:accountId` | Same as above, any account id works |
| 10 | Mass Assignment — self-registration as admin | CWE-915 | A01/A04 | `routes/auth.js POST /register` | Register with `"role":"admin"` in body |
| 11 | Mass Assignment / Missing Authz on profile update | CWE-915, CWE-862 | A01 Broken Access Control | `routes/users.js PUT /:id` | `PUT /api/users/2 {"role":"admin"}` as any logged-in user |
| 12 | Stored XSS via transaction note | CWE-79 | A03 Injection | `routes/transactions.js POST /transfer` → rendered in `frontend/dashboard.html` `innerHTML` | Note: `<img src=x onerror=alert(document.cookie)>` |
| 13 | CSRF on quick-transfer | CWE-352 | A01 Broken Access Control | `routes/transactions.js GET /quick-transfer` | Open `attacker-poc/csrf-poc.html` while logged in |
| 14 | Missing/weak cookie flags | CWE-614 | A05 Security Misconfig | `routes/auth.js` (`res.cookie('token', ...)`) | Inspect `Set-Cookie` header — no `Secure`, `HttpOnly` disabled, no `SameSite` |
| 15 | Verbose error messages / stack traces | CWE-209 | A05 Security Misconfig | `server.js` error handler, `routes/auth.js` DB errors | Trigger any 500 (e.g. malformed SQLi payload) |
| 16 | Permissive CORS (`origin: '*'`) | CWE-942 | A05 Security Misconfig | `server.js` | Inspect `Access-Control-Allow-Origin` header |
| 17 | Missing security headers (CSP, X-Frame-Options, HSTS, etc.) | CWE-1021 (Clickjacking) / CWE-693 | A05 Security Misconfig | `server.js` (no helmet) | Any response — check headers with curl/ZAP passive scan |
| 18 | Unrestricted file upload | CWE-434 | A04 Insecure Design | `routes/upload.js POST /avatar` | Upload a `.html`/`.svg` file, then load it from `/uploads/...` |
| 19 | Path traversal via upload filename | CWE-22 | A01 Broken Access Control | `routes/upload.js` (`file.originalname` used raw) | Upload with a crafted filename containing `../` sequences |
| 20 | OS Command Injection | CWE-78 | A03 Injection | `routes/export.js GET /statement` | `?account=ACC10001&format=csv;id` (unsanitized shell concat) |
| 21 | No rate limiting / brute-force protection | CWE-307 | A07 Auth Failures | `routes/auth.js POST /login` | Script repeated login attempts — no lockout, no delay |
| 22 | Predictable resource IDs (account enumeration) | CWE-330 / CWE-639 | A01 Broken Access Control | `db/db.js` accounts table, sequential `id` | Iterate `GET /api/accounts/1..N` |
| 23 | Business-logic flaw: no balance/ownership check on transfer | CWE-841 | A04 Insecure Design | `routes/transactions.js POST /transfer` | Transfer from an account you don't own, or send a negative `amount` |
| 24 | Sensitive data over-exposure in API response | CWE-200 | A01/A02 | `routes/users.js GET /` | Response includes every user's plaintext password |

## Suggested tools per category

- **SQLi (1–3):** sqlmap, ZAP active scan, Burp Scanner
- **Auth/JWT (5–6, 21):** jwt_tool, Burp, manual curl scripts
- **Access control (7–9, 11, 13, 22):** manual testing / Burp Autorize extension, ZAP
- **XSS (12):** ZAP, Burp, manual payloads
- **Misconfig (14–17):** ZAP passive scan, `curl -I`, Mozilla Observatory-style header checks
- **File upload (18–19):** Burp Repeater, manual
- **Command injection (20):** manual + ZAP active scan
- **SAST on source (all):** Semgrep (`p/owasp-top-ten` ruleset), CodeQL, Snyk Code
- **SCA:** `npm audit`, Snyk Open Source

## Notes for your report
- This app has **no automated fixes applied** — that's intentional so your
  scanner's findings are the whole story. If your project also wants a
  "before/after remediation" section, patch one bug per class (e.g., switch
  to parameterized `paramQuery` everywhere, add `helmet`, hash passwords
  with bcrypt, add CSRF tokens) and re-run the same scan for comparison.
- Treat this exactly like DVWA/Juice Shop: only run it against your own
  local instance, never expose it on a network others can reach.
