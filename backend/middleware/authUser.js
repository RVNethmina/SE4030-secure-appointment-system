import { getTokenFromRequest, verifyToken } from "../utils/token.js";

// user authentication middleware
const authUser = async (req, res, next) => {
  try {
    const token = getTokenFromRequest(req, ["token"]);

    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    const token_decode = verifyToken(token);

    // Only a patient token may call patient endpoints. Previously any valid
    // token was accepted, so a doctor or admin token was silently treated as a
    // patient session (CWE-863: incorrect authorization).
    if (token_decode.role !== "user" || !token_decode.id) {
      return res
        .status(403)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    // Trust ONLY the verified token for identity. Controllers read req.auth and
    // never req.body.userId, so a client-supplied userId (JSON or multipart
    // field) can never select another user's data (IDOR — CWE-639).
    req.auth = { userId: String(token_decode.id), role: "user" };

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session, please log in again.",
    });
  }
};

export default authUser;
