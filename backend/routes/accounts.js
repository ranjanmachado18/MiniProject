const express = require('express');
const router = express.Router();
const { paramQuery, rawQuery } = require('../db/db');
const { verifyToken } = require('../middleware/auth');

// -----------------------------------------------------------------------
// GET /api/accounts/:id
// VULNERABILITY (CWE-639 Insecure Direct Object Reference / Broken Access
// Control): any authenticated user can view ANY account by guessing/
// incrementing the numeric id -- no ownership check against req.user.id.
// -----------------------------------------------------------------------
router.get('/:id', verifyToken, (req, res) => {
  paramQuery(`SELECT * FROM accounts WHERE id = ?`, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  });
});

// -----------------------------------------------------------------------
// GET /api/accounts?owner=alice
// VULNERABILITY (CWE-89 SQL Injection) via query string, e.g.:
//   /api/accounts?owner=alice' UNION SELECT id,user_id,account_number,balance FROM accounts--
// -----------------------------------------------------------------------
router.get('/', verifyToken, (req, res) => {
  const owner = req.query.owner || '';
  const sql = `SELECT accounts.* FROM accounts
               JOIN users ON users.id = accounts.user_id
               WHERE users.username LIKE '%${owner}%'`;
  rawQuery(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message, query: sql });
    res.json(rows);
  });
});

module.exports = router;
