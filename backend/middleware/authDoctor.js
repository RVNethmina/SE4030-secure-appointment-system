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

    // Reject any token that is not a doctor token (e.g. a user/admin token).
    if (token_decode.role && token_decode.role !== "doctor") {
      return res
        .status(403)
        .json({ success: false, message: "Not Authorised for the doctor panel." });
    }

    // Identity comes ONLY from the verified token, never from the request body.
    req.auth = { docId: token_decode.id };
    req.body.docId = token_decode.id;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session, please log in again.",
    });
  }
};

export default authDoctor;
