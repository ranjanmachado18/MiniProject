const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const { verifyToken } = require('../middleware/auth');

// -----------------------------------------------------------------------
// GET /api/export/statement?account=ACC10002&format=csv
// VULNERABILITY (CWE-78 OS Command Injection): the "format" (and account)
// query params are concatenated directly into a shell command. Try:
//   /api/export/statement?account=ACC10002&format=csv; whoami
// -----------------------------------------------------------------------
router.get('/statement', verifyToken, (req, res) => {
  const account = req.query.account || 'ACC10001';
  const format = req.query.format || 'csv';

  // Simulated "export tool" invocation -- deliberately unsafe string build.
  const cmd = `echo "Generating ${format} statement for account ${account}" && date`;

  exec(cmd, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: stderr || err.message, cmd });
    res.json({ output: stdout, cmd }); // cmd echoed back too (info disclosure)
  });
});

module.exports = router;
