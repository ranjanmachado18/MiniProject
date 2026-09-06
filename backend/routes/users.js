const express = require('express');
const router = express.Router();
const { paramQuery, rawQuery } = require('../db/db');
const { verifyToken } = require('../middleware/auth');

// -----------------------------------------------------------------------
// GET /api/users
// VULNERABILITY (CWE-200 / CWE-359 Sensitive Data Exposure): returns the
// full user table INCLUDING the plaintext `password` column to any
// authenticated user, regardless of role.
// VULNERABILITY (CWE-285 Broken Function Level Authorization): this should
// be admin-only but only checks that *some* valid-looking token exists.
// -----------------------------------------------------------------------
router.get('/', verifyToken, (req, res) => {
  paramQuery(`SELECT * FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows); // includes password field on purpose
  });
});

// -----------------------------------------------------------------------
// GET /api/users/search?q=ali
// VULNERABILITY (CWE-89 SQL Injection), second injection point using a
// different query shape than /api/accounts for scanner-coverage variety.
// -----------------------------------------------------------------------
router.get('/search', verifyToken, (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT id, username, email, full_name, role FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;
  rawQuery(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message, query: sql });
    res.json(rows);
  });
});

// -----------------------------------------------------------------------
// PUT /api/users/:id
// VULNERABILITY (CWE-915 Mass Assignment + CWE-862 Missing Authorization):
// any logged-in user can PUT to any user id and set arbitrary fields,
// including role, on ANY account (not just their own) -- privilege
// escalation ("become admin by editing user id 2's role").
// -----------------------------------------------------------------------
router.put('/:id', verifyToken, (req, res) => {
  const fields = req.body || {};
  const allowed = ['email', 'full_name', 'role', 'password']; // role/password should never be here
  const sets = [];
  const values = [];
  for (const key of allowed) {
    if (fields[key] !== undefined) {
      sets.push(`${key} = ?`);
      values.push(fields[key]);
    }
  }
  if (!sets.length) return res.status(400).json({ error: 'No updatable fields provided' });
  values.push(req.params.id);
  const { run } = require('../db/db');
  run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, values, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: this.changes });
  });
});

module.exports = router;
