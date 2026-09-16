import bcrypt from "bcrypt";

/**
 * A bcrypt hash of a random throw-away value. Login handlers compare against
 * it when the account does not exist (or has no local password), so an
 * unknown email takes as long as a wrong password and response timing no
 * longer reveals which accounts exist (CWE-208 / CWE-204).
 */
export const DUMMY_PASSWORD_HASH = bcrypt.hashSync(
  `no-such-account-${Math.random()}`,
  10
);

/**
 * Compare a login attempt against a stored hash in constant work, even when
 * there is no stored hash. Resolves to false for missing hashes instead of
 * throwing (bcrypt rejects undefined hashes, which previously surfaced as a
 * 500 and exposed Google-only accounts).
 */
export async function verifyPassword(password, storedHash) {
  const isMatch = await bcrypt.compare(password, storedHash || DUMMY_PASSWORD_HASH);
  return Boolean(storedHash) && isMatch;
}
