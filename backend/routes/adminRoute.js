import express from "express";
import {
  addDoctor,
  allDoctors,
  loginAdmin,
  appointmentsAdmin,
  appointmentCancel,
  adminDashboard,
} from "../controllers/adminController.js";
import upload, { verifyImageSignature } from "../middleware/multer.js";
import authAdmin from "../middleware/authAdmin.js";
import { authLimiter } from "../middleware/rateLimiter.js";
import { changeAvailability } from "../controllers/doctorController.js";

const adminRouter = express.Router();

// Authenticate first, then accept the upload, then verify it is a real image.
adminRouter.post(
  "/add-doctor",
  authAdmin,
  upload.single("image"),
  verifyImageSignature,
  addDoctor
);
adminRouter.post("/login", authLimiter, loginAdmin);
adminRouter.post("/all-doctors", authAdmin, allDoctors);
adminRouter.post("/change-availability", authAdmin, changeAvailability);
adminRouter.post("/cancel-appointment", authAdmin, appointmentCancel);

adminRouter.get("/appointments", authAdmin, appointmentsAdmin);
adminRouter.get("/dashboard", authAdmin, adminDashboard);

export default adminRouter;
