import jwt from "jsonwebtoken";

/**
 * Centralised JWT helpers.
 *
 * Security properties enforced here (previously missing):
 *  - a single place that guarantees every token is signed with an expiry
 *    (CWE-613: insufficient session expiration);
 *  - a boot-time check that JWT_SECRET is present and strong enough
 *    (the original used the 4-char secret 'RBRO' — CWE-521/CWE-330);
 *  - one tolerant way to read a bearer token from a request, so the whole
 *    codebase parses `Authorization: Bearer <token>` consistently.
 */

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1d";

// Pin the signing algorithm. Verification only accepts HS256, so a token
// re-signed with "none" or any other algorithm is rejected outright
// (algorithm-confusion attacks, CWE-347).
const JWT_ALGORITHM = "HS256";

// Fail fast on a weak/missing secret rather than silently accepting forgeable tokens.
export function assertJwtSecret() {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
      "JWT_SECRET is missing or too weak. Set a random secret of at least 32 " +
        "characters in the environment (e.g. `node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\"`)."
    );
  }
}

/**
 * Sign a short-lived access token. `payload` should carry only non-sensitive
 * claims such as the subject id and role.
 */
export function signAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: JWT_ALGORITHM,
    expiresIn: JWT_EXPIRES_IN,
  });
}

export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
}

/**
 * Extract a token from a request. Prefers the standard
 * `Authorization: Bearer <token>` header, but also accepts the legacy custom
 * headers (`token`, `atoken`, `dtoken`) the original frontend/admin panels send,
 * so hardening the backend does not break the existing clients.
 */
export function getTokenFromRequest(req, legacyHeaderNames = []) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  for (const name of legacyHeaderNames) {
    const value = req.headers[name] || req.headers[name.toLowerCase()];
    if (value) return value;
  }
  return null;
}
