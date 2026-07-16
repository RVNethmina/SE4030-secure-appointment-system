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

    // Trust ONLY the token for identity. Attach to req.auth (not req.body) so a
    // client cannot smuggle a different userId in the request body and have it
    // overwrite the authenticated identity (IDOR — CWE-639).
    req.auth = { userId: token_decode.id };
    req.body.userId = token_decode.id;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session, please log in again.",
    });
  }
};

export default authUser;
