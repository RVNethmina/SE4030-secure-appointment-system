import doctorModel from "../models/doctorModel.js";
import { signAccessToken } from "../utils/token.js";
import { verifyPassword } from "../utils/password.js";
import appointmentModel from "../models/AppointmentModel.js";

const changeAvailability = async (req, res) => {
  try {
    const { docId } = req.body;

    const docData = await doctorModel.findById(docId);
    await doctorModel.findByIdAndUpdate(docId, {
      available: !docData.available,
    });
    res.json({ success: true, message: "Availability Changed" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

const doctorList = async (req, res) => {
  // we get all data from doctorModel.find({}) -> {}
  try {
    const doctors = await doctorModel.find({}).select(["-password", "-email"]);
    res.json({ success: true, doctors });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API for doctor Login

const loginDoctor = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Reject non-string inputs to prevent NoSQL operator injection (CWE-943).
    if (typeof email !== "string" || typeof password !== "string") {
      return res.json({ success: false, message: "Invalid Credentials!" });
    }

    const doctor = await doctorModel.findOne({ email });

    // Same bcrypt work whether or not the doctor exists (no timing oracle).
    const isMatch = await verifyPassword(password, doctor?.password);

    if (doctor && isMatch) {
      const token = signAccessToken({ id: doctor._id, role: "doctor" });

      res.json({ success: true, token });
    } else {
      return res.json({ success: false, message: "Invalid Credentials!" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API for get all appointsments for doctor panel

const appointmentsDoctor = async (req, res) => {
  try {
    //get docid from the verified doctor token
    const { docId } = req.auth;

    //find appointments for this relevent doctor
    const appointments = await appointmentModel.find({ docId });

    //send this data
    res.json({ success: true, appointments });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to mark appointments completed for doctor panel
const appointmentComplete = async (req, res) => {
  try {
    const { docId } = req.auth;
    const { appointmentId } = req.body;
    const appointmentData = await appointmentModel.findById(appointmentId);

    if (appointmentData && appointmentData.docId === docId) {
      await appointmentModel.findByIdAndUpdate(appointmentId, {isCompleted: true});
      return res.json({ success: true, message: "Appointment Completed!" });
    } else {
      return res.json({ success: false, message: "Mark failed!" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};

//API to cancel appointments for doctor panel
const appointmentCancel = async (req, res) => {
  try {
    const { docId } = req.auth;
    const { appointmentId } = req.body;
    const appointmentData = await appointmentModel.findById(appointmentId);

    if (appointmentData && appointmentData.docId === docId) {
      await appointmentModel.findByIdAndUpdate(appointmentId, {cancelled: true });
      return res.json({ success: true, message: "Appointment Cancelled!" });
    } else {
      return res.json({ success: false, message: "Cancellationfailed!" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};


//API to get dashboard data for doctor panel
const doctorDashboard = async (req,res) => {
  
  try {

    const { docId } = req.auth
    const appointments = await appointmentModel.find({docId})

    let earnings = 0

    appointments.map((item)=>{

      if(item.isCompleted || item.payment) {
        earnings += item.amount
      }
    })

    let patients = []

    appointments.map((item)=>{

      if(!patients.includes(item.userId)){
        patients.push(item.userId)
      }
    })

    const dashData = {
      earnings,
      appointments:appointments.length,
      patients:patients.length,
      latestAppointments:appointments.reverse().slice(0,5)
    }

    res.json({success:true,dashData})
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
};


//API to get Doctor profile for doctor panel
const doctorProfile = async (req,res) => {

  try {

    const {docId} = req.auth

    const profileData = await doctorModel.findById(docId).select('-password')

    res.json({success:true,profileData})
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
  
}


//API to update doctor profile data from doctor panel
const updateDoctorProfile = async (req,res) => {
  
  try {

    const { docId } = req.auth
    const { fees, address, available } = req.body

    await doctorModel.findByIdAndUpdate(docId,{fees,address,available})

    res.json({success:true,message:'Profile Updated!'})
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }

}

export {
  changeAvailability,
  doctorList,
  loginDoctor,
  appointmentsDoctor,
  appointmentCancel,
  appointmentComplete,
  doctorDashboard,
  updateDoctorProfile,
  doctorProfile
};
