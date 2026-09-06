const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const { init } = require('./db/db');

const authRoutes = require('./routes/auth');
const accountRoutes = require('./routes/accounts');
const transactionRoutes = require('./routes/transactions');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');
const uploadRoutes = require('./routes/upload');
const exportRoutes = require('./routes/export');

const app = express();
const PORT = process.env.PORT || 4000;

init();

// VULNERABILITY (CWE-16 Security Misconfiguration): permissive CORS allows
// any origin to make credentialed-looking requests, and no security headers
// (no helmet: missing CSP, X-Frame-Options, HSTS, etc.) are set anywhere.
app.use(cors({ origin: 'http://localhost:5500', credentials: true }));
app.use(express.json());
app.use(cookieParser());

// VULNERABILITY: uploaded files (including any uploaded .html/.svg) are
// served statically, enabling stored XSS / content-type confusion via
// uploaded files (CWE-434 follow-on).
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use('/api/auth', authRoutes);
app.use('/api/accounts', accountRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/export', exportRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok', env: process.env.NODE_ENV || 'development' }));

// VULNERABILITY (CWE-209): global error handler leaks stack traces to the client.
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(PORT, () => {
  console.log(`VulnBank API (intentionally vulnerable) listening on http://localhost:${PORT}`);
  console.log(`This app is for security-scanning / educational use ONLY. Do not deploy publicly.`);
});
