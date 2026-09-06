# VulnBank — Intentionally Vulnerable Banking Web App
### For security-scanning / AppSec mini-project use only

VulnBank is a small full-stack "banking" app (REST API + web UI) built
**on purpose with realistic, documented vulnerabilities**, so you can point
your own tools at it: API scanners (OWASP ZAP, Postman/Newman + security
tests, Burp Suite), SAST/source-code scanners (Semgrep, CodeQL, Snyk Code,
SonarQube), SCA/dependency scanners (npm audit, Snyk, Dependabot), and
DAST fuzzers (sqlmap, nikto, ffuf).

**⚠️ Run this only on `localhost` / an isolated VM. Never deploy it to the
public internet or a shared network — it is deliberately broken.**

## Stack
- Backend: Node.js + Express, SQLite (file-based, zero setup)
- Frontend: plain HTML/CSS/JS (no build step)
- Auth: JWT (deliberately weak — see `VULNERABILITIES.md`)

## Setup

```bash
# 1) Backend
cd backend
npm install
npm start
# API on http://localhost:4000

# 2) Frontend (separate terminal)
cd frontend
npm install
npm start
# UI on http://localhost:5500
```

The SQLite DB (`backend/db/vulnbank.sqlite`) is created and seeded
automatically on first run with these accounts:

| username | password  | role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | alice123  | user  |
| bob      | bob123    | user  |

## Project layout

```
vulnbank/
├── backend/           # Express REST API (the main scan target)
│   ├── routes/        # auth, accounts, transactions, users, admin, upload, export
│   ├── middleware/     # weak JWT auth
│   └── db/             # SQLite init + seed
├── frontend/          # Login, dashboard, transfer, admin pages
├── attacker-poc/       # Standalone CSRF proof-of-concept page (host separately)
└── VULNERABILITIES.md  # Full vulnerability catalogue with CWE IDs + how to trigger each
```

## Using it for your mini-project

1. **Source-code scanning (SAST):** run Semgrep / CodeQL / SonarQube /
   Snyk Code against `backend/`. Compare what it flags against
   `VULNERABILITIES.md` — this becomes your true-positive/false-negative
   analysis section.
2. **API scanning (DAST):** import the routes into Postman or OWASP ZAP's
   API scan (point it at `http://localhost:4000`), authenticate as `alice`,
   and let it crawl. Try `sqlmap -u "http://localhost:4000/api/accounts?owner=alice" --headers="Authorization: Bearer <token>"`.
3. **Dependency scanning (SCA):** `npm audit` in `backend/` for known-CVE
   findings in the dependency tree, separate from the intentional app-level
   bugs.
4. **Manual/exploit verification:** use `attacker-poc/csrf-poc.html` to
   demonstrate the CSRF finding end-to-end for your report.

## Report scaffolding
`VULNERABILITIES.md` is written so you can basically lift it into your
project report: each entry has a CWE ID, OWASP Top 10 category, file/line
area, and a repro. Fill in your scanner's actual output next to each one
(detected / missed) to build your comparison table.
