const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { verifyToken } = require('../middleware/auth');

// -----------------------------------------------------------------------
// VULNERABILITY (CWE-434 Unrestricted Upload of File with Dangerous Type):
// no MIME/extension allow-list, so .html/.svg/.js/.php etc. can be uploaded.
// VULNERABILITY (CWE-22 Path Traversal): the original filename (attacker
// controlled) is used almost as-is, allowing "../../server.js"-style names
// to attempt writing outside the uploads directory.
// -----------------------------------------------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '..', 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname) // no sanitization
});
const upload = multer({ storage }); // no fileFilter, no limits set

router.post('/avatar', verifyToken, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ path: `/uploads/${req.file.filename}` });
});

module.exports = router;
