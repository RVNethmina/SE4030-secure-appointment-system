import { OAuth2Client } from "google-auth-library";
import userModel from "../models/userModel.js";
import { signAccessToken } from "../utils/token.js";

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

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
    const { credential } = req.body;

    if (typeof credential !== "string" || !credential) {
      return res
        .status(400)
        .json({ success: false, message: "Missing Google credential." });
    }

    if (!process.env.GOOGLE_CLIENT_ID) {
      return res
        .status(500)
        .json({ success: false, message: "Google sign-in is not configured." });
    }

    // Verify signature, issuer, audience (our client id) and expiry.
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // Only accept Google-verified email addresses.
    if (!payload || !payload.email || !payload.email_verified) {
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
        user.googleId = googleId;
        if (user.authProvider === "local") user.authProvider = "google";
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

export { googleAuth };
