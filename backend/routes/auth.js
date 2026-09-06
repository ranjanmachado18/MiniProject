const express = require('express');
const router = express.Router();
const { rawQuery, run } = require('../db/db');
const { signToken } = require('../middleware/auth');

// In-memory failed-login counter that is NEVER actually enforced anywhere
// below -- present only to look like protection exists (a common real-world
// "security theater" misconfiguration scanners/pentesters flag).
const failedAttempts = {};

// -----------------------------------------------------------------------
// POST /api/auth/login
// VULNERABILITY (CWE-89 SQL Injection): username/password are concatenated
// directly into the SQL string. Try: username = admin' -- 
// VULNERABILITY (CWE-307): no rate limiting / account lockout on failures.
// -----------------------------------------------------------------------
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  rawQuery(sql, (err, rows) => {
    if (err) {
      // VULNERABILITY (CWE-209 Information Exposure Through Error Message):
      // raw DB error / query is reflected back to the client.
      return res.status(500).json({ error: 'Database error', details: err.message, query: sql });
    }
    if (!rows || rows.length === 0) {
      failedAttempts[username] = (failedAttempts[username] || 0) + 1;
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = rows[0];
    const token = signToken(user);
    // Also set a cookie version of the "session" for the legacy quick-transfer
    // endpoint (see routes/transactions.js /quick-transfer) which is
    // intentionally CSRF-vulnerable.
    res.cookie('token', token, { httpOnly: false }); // VULNERABILITY: no Secure/SameSite flags (CWE-614/CWE-352)
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name }
      // NOTE: see /api/users for a route that leaks the password field too.
    });
  });
});

// -----------------------------------------------------------------------
// POST /api/auth/register
// VULNERABILITY (CWE-915 Mass Assignment): the client can pass "role":"admin"
// directly in the JSON body and self-register as an administrator.
// VULNERABILITY (CWE-256): password stored in plaintext, no complexity rules.
// -----------------------------------------------------------------------
router.post('/register', (req, res) => {
  const body = req.body || {};
  const { username, email, password, full_name } = body;
  const role = body.role || 'user'; // <-- mass assignment: client-controlled

  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  run(
    `INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)`,
    [username, email || '', password, full_name || '', role],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error', details: err.message });
      run(`INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)`,
        [this.lastID, 'ACC1' + (1000 + this.lastID), 1000.0],
        () => {
          res.status(201).json({ id: this.lastID, username, role });
        });
    }
  );
});

module.exports = router;
