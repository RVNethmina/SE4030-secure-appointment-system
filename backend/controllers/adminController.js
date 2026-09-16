// API for adding doctor
import validator from "validator";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { v2 as cloudinary } from "cloudinary";
import doctorModel from "../models/doctorModel.js";
import { signAccessToken } from "../utils/token.js";
import appointmentModel from "../models/AppointmentModel.js";
import userModel from "../models/userModel.js";
import { removeUploadedFile } from "../middleware/multer.js";
import { isObjectId } from "../utils/validation.js";
import { releaseDoctorSlot } from "../utils/slots.js";

// Constant-time string comparison to avoid leaking the admin credentials via
// response-timing side channels (CWE-208). Both values are hashed first so the
// comparison always runs over equal-length buffers; the previous early return
// on a length mismatch leaked the length of the admin password.
const safeEqual = (a, b) => {
  const ah = crypto.createHash("sha256").update(String(a)).digest();
  const bh = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ah, bh);
};

// Fail fast at boot on a missing or weak bootstrap admin credential. The
// original shipped ADMIN_PASSWORD='qwerty123', and the admin role can add
// doctors and read every patient's appointments.
export function assertAdminCredentials() {
  const email = process.env.ADMIN_EMAIL || "";
  const password = process.env.ADMIN_PASSWORD || "";
  if (
    !validator.isEmail(email) ||
    !validator.isStrongPassword(password, { minLength: 12 })
  ) {
    throw new Error(
      "ADMIN_EMAIL must be a valid email and ADMIN_PASSWORD must be at least " +
        "12 characters with upper- and lower-case letters, a number and a symbol."
    );
  }
}

const addDoctor = async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      speciality,
      degree,
      experience,
      about,
      fees,
      address,
    } = req.body;
    const imageFile = req.file;

    //checking for all data to add doctor

    if (
      !name ||
      !email ||
      !password ||
      !speciality ||
      !degree ||
      !experience ||
      !about ||
      !fees ||
      !address
    ) {
      return res.json({ success: false, message: "Missing Details" });
    }


    if (!req.file) {
      return res.json({ success: false, message: "Image file is required" });
    }

    //validating email format
    if (!validator.isEmail(email)) {
      return res.json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    //validate strong password: min length + upper/lower/number/symbol
    if (
      !validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      return res.json({
        success: false,
        message:
          "Weak password: use at least 8 characters with upper- and lower-case letters, a number and a symbol.",
      });
    }

    //hashing doctor password
    //number 5 - 10 can be used, if we use higher number takes more time
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    //upload image to cloudinary
    const imageUpload = await cloudinary.uploader.upload(imageFile.path, {
      resource_type: "image",
    });
    const imageUrl = imageUpload.secure_url;

    const doctorData = {
      name,
      email,
      image: imageUrl,
      password: hashedPassword,
      speciality,
      degree,
      experience,
      about,
      fees,
      address: JSON.parse(address),
      date: Date.now(),
    };

    const newDoctor = new doctorModel(doctorData);
    await newDoctor.save();

    res.json({ success: true, message: "Doctor Added!" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  } finally {
    // Remove the temp upload on every path (validation failures included).
    await removeUploadedFile(req.file);
  }
};

//api for admin login

const loginAdmin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== "string" || typeof password !== "string") {
      return res
        .status(400)
        .json({ success: false, message: "Invalid Credentials!" });
    }

    const emailOk = safeEqual(email, process.env.ADMIN_EMAIL);
    const passOk = safeEqual(password, process.env.ADMIN_PASSWORD);

    if (emailOk && passOk) {
      // Sign a proper token carrying a role claim + expiry — never the raw
      // credential string.
      const token = signAccessToken({ role: "admin", email });
      return res.json({ success: true, token });
    }

    return res
      .status(401)
      .json({ success: false, message: "Invalid Credentials!" });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Login failed, please try again." });
  }
};

//API to get all doctors list

const allDoctors = async (req, res) => {
  try {
    // -password remove the password from the response
    const doctors = await doctorModel.find({}).select("-password");
    res.json({ success: true, doctors });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to get All Appointments list
const appointmentsAdmin = async (req, res) => {
  try {
    //get all appointments
    const appointments = await appointmentModel.find({});
    res.json({ success: true, appointments });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API for appointment cancellation
const appointmentCancel = async (req, res) => {
  try {
    const { appointmentId } = req.body;

    if (!isObjectId(appointmentId)) {
      return res.status(400).json({ success: false, message: "Invalid appointment." });
    }

    // Atomic state transition: a missing, already-cancelled or completed
    // appointment is refused instead of crashing on null or releasing a slot
    // a second time.
    const appointmentData = await appointmentModel.findOneAndUpdate(
      { _id: appointmentId, cancelled: false, isCompleted: false },
      { cancelled: true }
    );

    if (!appointmentData) {
      return res.json({ success: false, message: "Appointment can no longer be cancelled!" });
    }

    //releasing cancelled doctor slot
    await releaseDoctorSlot(appointmentData);

    res.json({ success: true, message: "Appointment Cancelled!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to get dashboard data for admin panel

const adminDashboard = async (req, res) => {

  try {

    const doctors =  await doctorModel.find({})
    const users = await userModel.find({})
    const appointments = await appointmentModel.find({})

    const dashData = {
        doctors: doctors.length,
        appointments : appointments.length,
        patients: users.length,
        latestAppointments: appointments.reverse().slice(0,5)

    }

    res.json({success:true, dashData})

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

export {
  addDoctor,
  loginAdmin,
  allDoctors,
  appointmentsAdmin,
  appointmentCancel,
  adminDashboard
};
