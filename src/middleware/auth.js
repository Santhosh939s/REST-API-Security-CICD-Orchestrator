const jwt = require('jsonwebtoken');

// =========================================================================================
// [VULNERABILITY: OWASP Top 10 - Hardcoded Secrets (CWE-798 / A05:2021 - Security Misconfiguration)]
// Description: Cryptographic signing secret is hardcoded directly into the application source.
// Detection: Identified by Semgrep SAST rules (e.g., generic.secrets.security.detected-jwt-secret).
// Impact: Any adversary reading repository code can forge valid arbitrary JWT tokens.
// =========================================================================================
const HARDCODED_JWT_SECRET = "supersecret_jwt_devsecops_orchestrator_key_2026";

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Access Denied: Missing Authorization Header' });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
  if (!token) {
    return res.status(401).json({ error: 'Access Denied: Malformed Bearer Token' });
  }

  try {
    // Intentionally trusting the hardcoded secret or environment variable
    const secret = process.env.JWT_SECRET || HARDCODED_JWT_SECRET;
    const verified = jwt.verify(token, secret);
    req.user = verified;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or Expired Token' });
  }
};

module.exports = { verifyToken, HARDCODED_JWT_SECRET };
