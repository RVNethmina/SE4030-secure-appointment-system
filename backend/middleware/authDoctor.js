import { getTokenFromRequest, verifyToken } from "../utils/token.js";

// doctor authentication middleware
const authDoctor = async (req, res, next) => {
  try {
    const dtoken = getTokenFromRequest(req, ["dtoken"]);

    if (!dtoken) {
      return res
        .status(401)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    const token_decode = verifyToken(dtoken);

    // Require an explicit doctor role. The previous check only rejected tokens
    // that carried a *different* role, so any token without a role claim was
    // accepted as a doctor session (CWE-863).
    if (token_decode.role !== "doctor" || !token_decode.id) {
      return res
        .status(403)
        .json({ success: false, message: "Not Authorised for the doctor panel." });
    }

    // Identity comes ONLY from the verified token, never from the request body.
    req.auth = { docId: String(token_decode.id), role: "doctor" };

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session, please log in again.",
    });
  }
};

export default authDoctor;
