import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";
import userModel from "../models/userModel.js";
import {
  signAccessToken,
  signNonceToken,
  verifyNonceToken,
} from "../utils/token.js";

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Ids (jti) of nonce tokens that were already used, mapped to their expiry.
// One-time use stops a captured { credential, nonceToken } pair from being
// replayed. In-memory is enough for a single API instance; a multi-instance
// deployment would keep these in Redis or a MongoDB TTL collection.
const usedNonceIds = new Map();

const consumeNonceId = (jti, exp) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  for (const [id, expiry] of usedNonceIds) {
    if (expiry < nowSeconds) usedNonceIds.delete(id);
  }
  if (!jti || usedNonceIds.has(jti)) return false;
  usedNonceIds.set(jti, exp);
  return true;
};

/**
 * Step 1 of Google sign-in: issue a random nonce. The browser passes it to
 * Google Identity Services, and Google embeds it in the signed ID token. The
 * signed nonceToken lets the backend check it later without server state.
 */
const googleNonce = (req, res) => {
  const nonce = crypto.randomBytes(32).toString("base64url");
  res.set("Cache-Control", "no-store");
  return res.json({ success: true, nonce, nonceToken: signNonceToken(nonce) });
};

/**
 * Google OpenID Connect sign-in (Google Identity Services flow).
 *
 * The frontend obtains a signed Google ID token (a JWT / OIDC id_token) and
 * POSTs it here as `credential`. We verify that token's signature and claims
 * against Google's public keys and our own client id, then issue our app's
 * own access token. A first-time Google user is provisioned automatically;
 * an existing local account with the same verified email is linked to Google.
 */
const googleAuth = async (req, res) => {
  try {
    const { credential, nonceToken } = req.body;

    if (
      typeof credential !== "string" ||
      !credential ||
      typeof nonceToken !== "string" ||
      !nonceToken
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Missing Google credential." });
    }

    if (!process.env.GOOGLE_CLIENT_ID) {
      return res
        .status(500)
        .json({ success: false, message: "Google sign-in is not configured." });
    }

    // The nonce token must be one we issued in the last few minutes.
    let nonceClaims;
    try {
      nonceClaims = verifyNonceToken(nonceToken);
    } catch {
      return res
        .status(401)
        .json({ success: false, message: "Google sign-in expired, please try again." });
    }

    // Verify signature, issuer, audience (our client id) and expiry.
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // OIDC nonce check: the ID token must have been requested for THIS nonce.
    // Without it, any valid ID token for our client id (leaked from logs, a
    // proxy, or minted for another login attempt) could be replayed here
    // until it expired (CWE-294 authentication bypass by capture-replay).
    if (!payload?.nonce || payload.nonce !== nonceClaims.nonce) {
      return res
        .status(401)
        .json({ success: false, message: "Google sign-in failed." });
    }

    if (!consumeNonceId(nonceClaims.jti, nonceClaims.exp)) {
      return res
        .status(401)
        .json({ success: false, message: "Google sign-in expired, please try again." });
    }

    // Only accept Google-verified email addresses.
    if (!payload.email || !payload.email_verified) {
      return res
        .status(401)
        .json({ success: false, message: "Google account email not verified." });
    }

    const { sub: googleId, email, name, picture } = payload;

    // Find by Google id first, then by email (to link an existing local account).
    let user = await userModel.findOne({ googleId });

    if (!user) {
      user = await userModel.findOne({ email });
      if (user) {
        // Link Google to the pre-existing local account.
        //
        // Account pre-hijacking defence: local sign-up never proves ownership
        // of the email address, so an attacker can register the victim's
        // address first and keep the password after the real owner signs in
        // with Google. Google has now verified ownership, so drop the
        // unverified local password and revoke every session issued before
        // this moment. The owner keeps access through Google sign-in.
        user.googleId = googleId;
        user.authProvider = "google";
        user.password = undefined;
        user.sessionsValidAfter = Math.floor(Date.now() / 1000);
        await user.save();
      } else {
        // Provision a new Google-backed account (no local password).
        user = await userModel.create({
          name: name || email.split("@")[0],
          email,
          authProvider: "google",
          googleId,
          ...(picture ? { image: picture } : {}),
        });
      }
    }

    const token = signAccessToken({ id: user._id, role: "user" });
    return res.json({ success: true, token });
  } catch (error) {
    console.error("[googleAuth]", error?.message);
    return res
      .status(401)
      .json({ success: false, message: "Google sign-in failed." });
  }
};

export { googleAuth, googleNonce };
