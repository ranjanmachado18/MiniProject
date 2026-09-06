const express = require('express');
const router = express.Router();
const { paramQuery, run } = require('../db/db');
const { verifyToken, requireAdmin } = require('../middleware/auth');

// -----------------------------------------------------------------------
// GET /api/admin/users  and  POST /api/admin/set-balance
// VULNERABILITY: requireAdmin only checks the `role` claim baked into the
// client-held JWT (see middleware/auth.js). Combined with the alg-confusion
// fallback and the register-time mass-assignment bug, a user can mint or
// obtain a token with role:"admin" and reach these without ever being
// granted admin in a trustworthy way.
// -----------------------------------------------------------------------
router.get('/users', verifyToken, requireAdmin, (req, res) => {
  paramQuery(`SELECT * FROM users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

router.post('/set-balance', verifyToken, requireAdmin, (req, res) => {
  const { account_id, balance } = req.body || {};
  run(`UPDATE accounts SET balance = ? WHERE id = ?`, [balance, account_id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: this.changes });
  });
});

module.exports = router;
