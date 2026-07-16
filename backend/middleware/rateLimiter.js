import rateLimit from "express-rate-limit";

/**
 * Strict limiter for authentication endpoints (login / register / OAuth).
 * Blunts online password brute-forcing and credential stuffing (CWE-307).
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts / IP / window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many attempts. Please try again in a few minutes.",
  },
});

/**
 * General limiter applied to the whole API as a DoS/abuse backstop.
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests, please slow down.",
  },
});
