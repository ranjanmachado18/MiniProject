// middleware/auth.js
const jwt = require('jsonwebtoken');

// VULNERABILITY (CWE-798 Use of Hard-coded Credentials / weak secret):
// Hard-coded, short, guessable JWT signing secret checked into source control.
const JWT_SECRET = 'secret123';

function signToken(user) {
  // VULNERABILITY: JWT payload includes role and is trusted as-is by the
  // rest of the app with no re-check against the DB (stale/forged role trust).
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '2h' }
  );
}

function verifyToken(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (req.cookies && req.cookies.token);

  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    // VULNERABILITY (CWE-347 Improper Verification of Cryptographic Signature):
    // decode() is used first and, on any verify error, the code below FALLS
    // BACK to trusting the decoded-but-unverified payload for convenience.
    // This mirrors a real-world "alg:none" / signature-bypass style bug some
    // scanners (and manual testers) specifically probe for.
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
    } catch (e) {
      payload = jwt.decode(token); // insecure fallback, no signature check
    }
    if (!payload) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// VULNERABILITY (CWE-285 Improper Authorization / Broken Function Level Authz):
// requireAdmin trusts req.user.role which came straight from the client-supplied
// JWT payload (see above) instead of re-checking the DB.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

module.exports = { signToken, verifyToken, requireAdmin, JWT_SECRET };
