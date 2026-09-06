const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { paramQuery, run } = require('../db/db');
const { verifyToken, JWT_SECRET } = require('../middleware/auth');

// -----------------------------------------------------------------------
// POST /api/transactions/transfer   (JWT-in-header, "modern" flow)
// VULNERABILITY (CWE-79 Stored XSS): `note` is stored as-is and the
// frontend renders it with innerHTML on the transaction history page.
// VULNERABILITY (CWE-841 / business logic): no check that from_account
// actually belongs to req.user, and no check that amount <= balance
// (allows negative-balance / arbitrary overdraft if amount is negative
// or huge -- try amount: -1000 to see balance increase).
// -----------------------------------------------------------------------
router.post('/transfer', verifyToken, (req, res) => {
  const { from_account, to_account, amount, note } = req.body || {};
  if (!from_account || !to_account || amount === undefined) {
    return res.status(400).json({ error: 'from_account, to_account, amount required' });
  }

  run(`UPDATE accounts SET balance = balance - ? WHERE id = ?`, [amount, from_account], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    run(`UPDATE accounts SET balance = balance + ? WHERE id = ?`, [amount, to_account], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      run(
        `INSERT INTO transactions (from_account, to_account, amount, note) VALUES (?, ?, ?, ?)`,
        [from_account, to_account, amount, note || ''],
        function (err3) {
          if (err3) return res.status(500).json({ error: err3.message });
          res.json({ id: this.lastID, from_account, to_account, amount, note });
        }
      );
    });
  });
});

// -----------------------------------------------------------------------
// GET /api/transactions/quick-transfer?to=2&amount=500  (cookie-auth flow)
// VULNERABILITY (CWE-352 Cross-Site Request Forgery): this endpoint reads
// auth purely from the `token` cookie (set with no SameSite flag at login),
// accepts state-changing action via a simple GET, and has no CSRF token
// check. A malicious page can do:
//   <img src="http://victim-host/api/transactions/quick-transfer?to=9&amount=99999">
// while the victim is logged in, and the browser will attach the cookie.
// -----------------------------------------------------------------------
router.get('/quick-transfer', (req, res) => {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  let payload;
  try {
    payload = jwt.decode(token); // no signature verification here either
  } catch (e) {
    return res.status(401).json({ error: 'bad token' });
  }
  const { to, amount } = req.query;
  if (!to || !amount) return res.status(400).json({ error: 'to and amount query params required' });

  paramQuery(`SELECT id FROM accounts WHERE user_id = ?`, [payload.id], (err, rows) => {
    if (err || !rows.length) return res.status(400).json({ error: 'No source account' });
    const from = rows[0].id;
    run(`UPDATE accounts SET balance = balance - ? WHERE id = ?`, [amount, from], () => {
      run(`UPDATE accounts SET balance = balance + ? WHERE id = ?`, [amount, to], () => {
        run(`INSERT INTO transactions (from_account, to_account, amount, note) VALUES (?, ?, ?, ?)`,
          [from, to, amount, 'quick-transfer'], function () {
            res.json({ ok: true, id: this.lastID });
          });
      });
    });
  });
});

// -----------------------------------------------------------------------
// GET /api/transactions/account/:accountId
// VULNERABILITY (CWE-639 IDOR): no ownership check, any logged-in user can
// read any account's full transaction history by id.
// -----------------------------------------------------------------------
router.get('/account/:accountId', verifyToken, (req, res) => {
  paramQuery(
    `SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY created_at DESC`,
    [req.params.accountId, req.params.accountId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

module.exports = router;
