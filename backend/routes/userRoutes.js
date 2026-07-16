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
import upload from "../middleware/multer.js";
import { authLimiter } from "../middleware/rateLimiter.js";
import { googleAuth } from "../controllers/authController.js";


const useRouter = express.Router();

useRouter.post("/register", authLimiter, registerUser);
useRouter.post("/login", authLimiter, loginUser);
// Google OpenID Connect sign-in
useRouter.post("/auth/google", authLimiter, googleAuth);
useRouter.post(
  "/update-profile",
  upload.single("image"),
  authUser,
  updateProfile
);
useRouter.post("/book-appointment", authUser, bookAppointment);
useRouter.post("/cancel-appointment", authUser, cancelAppointment);

useRouter.get("/get-profile", authUser, getProfile);
useRouter.get("/appointments", authUser, listAppointment);

export default useRouter;
