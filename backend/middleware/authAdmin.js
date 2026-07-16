import { getTokenFromRequest, verifyToken } from "../utils/token.js";

// admin authentication middleware
const authAdmin = async (req, res, next) => {
  try {
    const atoken = getTokenFromRequest(req, ["atoken"]);

    if (!atoken) {
      return res
        .status(401)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    const token_decode = verifyToken(atoken);

    // Authorisation is decided by a signed `role` claim inside the token, NOT by
    // reconstructing "email+password" from environment variables. The old scheme
    // signed the literal ADMIN_EMAIL+ADMIN_PASSWORD string as the whole JWT
    // payload, so anyone who learned those (they were committed to git) could
    // mint an admin token, and the check leaked the credentials into the token.
    if (token_decode.role !== "admin") {
      return res
        .status(403)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    req.auth = { role: "admin", email: token_decode.email };
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session, please log in again.",
    });
  }
};

export default authAdmin;
