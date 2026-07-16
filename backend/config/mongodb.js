import mongoose from "mongoose";

const connectDB = async () => {
  mongoose.connection.on("connected", () => console.log("Database Connected!"));
  mongoose.connection.on("error", (err) =>
    console.error("MongoDB connection error:", err?.message)
  );

  try {
    await mongoose.connect(`${process.env.MONGODB_URI}/prescripto`, {
      serverSelectionTimeoutMS: 5000,
    });
  } catch (err) {
    // Don't let a failed initial DB connection crash the whole process with an
    // unhandled promise rejection; log it and let mongoose keep retrying.
    console.error("Initial MongoDB connection failed:", err?.message);
  }
};

export default connectDB;
