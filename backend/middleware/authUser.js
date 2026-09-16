import { getTokenFromRequest, verifyToken } from "../utils/token.js";
import userModel from "../models/userModel.js";

// user authentication middleware
const authUser = async (req, res, next) => {
  let token_decode;
  try {
    const token = getTokenFromRequest(req, ["token"]);

    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    token_decode = verifyToken(token);
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session, please log in again.",
    });
  }

  // Only a patient token may call patient endpoints. Previously any valid
  // token was accepted, so a doctor or admin token was silently treated as a
  // patient session (CWE-863: incorrect authorization).
  if (token_decode.role !== "user" || !token_decode.id) {
    return res
      .status(403)
      .json({ success: false, message: "Not Authorised, Login again!" });
  }

  try {
    // Reject tokens for deleted accounts and tokens issued before the
    // account's sessions were revoked (e.g. when Google sign-in takes over an
    // account whose local password may have been set by someone else).
    const account = await userModel
      .findById(token_decode.id)
      .select("sessionsValidAfter")
      .lean();

    if (!account || token_decode.iat < (account.sessionsValidAfter || 0)) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired session, please log in again.",
      });
    }
  } catch (error) {
    console.error("[authUser]", error?.message);
    return res
      .status(500)
      .json({ success: false, message: "Something went wrong. Please try again." });
  }

  // Trust ONLY the verified token for identity. Controllers read req.auth and
  // never req.body.userId, so a client-supplied userId (JSON or multipart
  // field) can never select another user's data (IDOR — CWE-639).
  req.auth = { userId: String(token_decode.id), role: "user" };

  next();
};

export default authUser;
