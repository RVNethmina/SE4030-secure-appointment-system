import validator from "validator";
import bcrypt from "bcrypt";
import userModel from "../models/userModel.js";
import { signAccessToken } from "../utils/token.js";
import { v2 as cloudinary } from "cloudinary";
import doctorModel from "../models/doctorModel.js";
import appointmentModel from "../models/AppointmentModel.js";
import razorpay from "razorpay";
import { removeUploadedFile } from "../middleware/multer.js";
import { verifyPassword } from "../utils/password.js";
import { isObjectId, isValidSlotDate, isValidSlotTime } from "../utils/validation.js";
import { reserveDoctorSlot, releaseDoctorSlot } from "../utils/slots.js";

// API to register user
const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !password || !email) {
      return res.json({ success: false, message: "Missing Details!" });
    }

    // Reject non-string inputs so an object like { "$ne": null } can never reach
    // a Mongo query (NoSQL injection — CWE-943).
    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.json({ success: false, message: "Invalid input." });
    }

    //validating email format
    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Enter a Valid Email!" });
    }

    //validating strong password: min length + upper/lower/number/symbol
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

    //Hasing user password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const userData = {
      name,
      email,
      password: hashedPassword,
    };

    const newUser = new userModel(userData);
    const user = await newUser.save();

    //create token for the user to login
    const token = signAccessToken({ id: user._id, role: "user" });

    res.json({ success: true, token });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API for user login
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Enforce string inputs: without this, { "email": { "$ne": null } } would
    // match the first user in the collection (NoSQL injection — CWE-943).
    if (typeof email !== "string" || typeof password !== "string") {
      return res.json({ success: false, message: "Invalid Credentials!" });
    }

    const user = await userModel.findOne({ email });

    // Always run one bcrypt comparison: unknown emails and Google-only
    // accounts (no local password) now fail exactly like a wrong password,
    // instead of returning early (timing oracle) or throwing a 500.
    const isMatch = await verifyPassword(password, user?.password);

    if (user && isMatch) {
      const token = signAccessToken({ id: user._id, role: "user" });
      res.json({ success: true, token });
    } else {
      res.json({ success: false, message: "Invalid Credentials!" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to get user profile data

const getProfile = async (req, res) => {
  try {
    const { userId } = req.auth;
    const userData = await userModel.findById(userId).select("-password");

    res.json({ success: true, userData });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to update user profile

const updateProfile = async (req, res) => {
  try {
    const { userId } = req.auth;
    const { name, phone, address, dob, gender } = req.body;

    const imageFile = req.file;

    if (!name || !phone || !dob || !gender) {
      return res.json({ success: false, message: "Data Missing!" });
    }

    await userModel.findByIdAndUpdate(userId, {
      name,
      phone,
      address: JSON.parse(address),
      dob,
      gender,
    });

    if (imageFile) {
      //upload image to cloudinary
      const imageUpload = await cloudinary.uploader.upload(imageFile.path, {
        resource_type: "image",
      });
      const imageURL = imageUpload.secure_url;

      await userModel.findByIdAndUpdate(userId, { image: imageURL });
    }

    res.json({ success: true, message: "Profile Updated!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  } finally {
    // The image now lives on Cloudinary; never leave the temp copy on disk.
    await removeUploadedFile(req.file);
  }
};

//API to book appointment

const bookAppointment = async (req, res) => {
  let reservation = null;
  try {
    //get data from the request
    const { userId } = req.auth;
    const { docId, slotDate, slotTime } = req.body;

    // Validate before any query: a non-ObjectId docId used to crash with a
    // 500, and unchecked slotDate/slotTime strings were used as keys inside
    // doctor.slots_booked (past dates, "__proto__", arbitrary junk).
    if (!isObjectId(docId) || !isValidSlotDate(slotDate) || !isValidSlotTime(slotTime)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid booking details." });
    }

    //getting user data (only the fields the doctor/admin views need)
    const userData = await userModel
      .findById(userId)
      .select("name image address gender dob phone")
      .lean();

    if (!userData) {
      return res
        .status(401)
        .json({ success: false, message: "Not Authorised, Login again!" });
    }

    // Check-and-book in ONE atomic update. The old code read slots_booked,
    // checked it in JS and wrote the whole object back later, so two
    // concurrent requests could both book the same slot (CWE-362).
    const docData = await reserveDoctorSlot(docId, slotDate, slotTime);

    if (!docData) {
      const doctor = await doctorModel.findById(docId).select("available").lean();
      if (!doctor) {
        return res.status(404).json({ success: false, message: "Doctor not found!" });
      }
      if (!doctor.available) {
        return res.json({ success: false, message: "Doctor not Available!" });
      }
      return res.json({ success: false, message: "Slot not Available!" });
    }
    reservation = { docId, slotDate, slotTime };

    //save appointment in the database
    await appointmentModel.create({
      userId,
      docId,
      userData,
      docData,
      amount: docData.fees,
      slotTime,
      slotDate,
      date: Date.now(),
    });
    reservation = null;

    res.json({ success: true, message: "Appointment Booked!" });
  } catch (error) {
    console.error(error);
    // Don't leave a slot blocked if the appointment could not be stored.
    if (reservation) await releaseDoctorSlot(reservation).catch(() => {});
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to get user Appointments for frontend my-appointment page
const listAppointment = async (req, res) => {
  try {
    const { userId } = req.auth;
    const appointments = await appointmentModel.find({ userId });

    res.json({ success: true, appointments });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to cancel appointment
const cancelAppointment = async (req, res) => {
  try {
    const { userId } = req.auth;
    const { appointmentId } = req.body;

    if (!isObjectId(appointmentId)) {
      return res.status(400).json({ success: false, message: "Unauthorised Action!" });
    }

    const appointmentData = await appointmentModel.findById(appointmentId);

    // Object-level authorisation: the appointment must belong to the caller.
    // String()-coerce both sides so an ObjectId vs string mismatch cannot make
    // the check pass or wrongly fail (IDOR — CWE-639). Also guard the not-found
    // case so we don't dereference null.
    if (!appointmentData || String(appointmentData.userId) !== String(userId)) {
      return res.json({ success: false, message: "Unauthorised Action!" });
    }

    // Only an active appointment can be cancelled. The state change is atomic
    // so repeated/concurrent cancels cannot release the slot twice, and a
    // completed appointment can no longer be flipped to cancelled.
    const cancelled = await appointmentModel.findOneAndUpdate(
      { _id: appointmentId, cancelled: false, isCompleted: false },
      { cancelled: true }
    );

    if (!cancelled) {
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

export {
  registerUser,
  loginUser,
  getProfile,
  updateProfile,
  bookAppointment,
  listAppointment,
  cancelAppointment,
};
