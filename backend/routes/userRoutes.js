import express from "express";
import {
  registerUser,
  loginUser,
  getProfile,
  updateProfile,
  bookAppointment,
  listAppointment,
  cancelAppointment,
} from "../controllers/UserController.js";
import authUser from "../middleware/authUser.js";
import upload, { verifyImageSignature } from "../middleware/multer.js";
import { authLimiter } from "../middleware/rateLimiter.js";
import { googleAuth, googleNonce } from "../controllers/authController.js";


const useRouter = express.Router();

useRouter.post("/register", authLimiter, registerUser);
useRouter.post("/login", authLimiter, loginUser);
// Google OpenID Connect sign-in: get a one-time nonce, then exchange the ID token
useRouter.get("/auth/google/nonce", googleNonce);
useRouter.post("/auth/google", authLimiter, googleAuth);
// authUser MUST run before multer: otherwise anonymous clients can write files
// to the server's disk before authentication is ever checked.
useRouter.post(
  "/update-profile",
  authUser,
  upload.single("image"),
  verifyImageSignature,
  updateProfile
);
useRouter.post("/book-appointment", authUser, bookAppointment);
useRouter.post("/cancel-appointment", authUser, cancelAppointment);

useRouter.get("/get-profile", authUser, getProfile);
useRouter.get("/appointments", authUser, listAppointment);

export default useRouter;
