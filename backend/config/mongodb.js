import mongoose from "mongoose";

const connectDB = async () => {
  mongoose.connection.on("connected", () => console.log("Database Connected!"));
  mongoose.connection.on("error", (err) =>
    console.error("MongoDB connection error:", err?.message)
  );

  try {
    // Select the database with dbName instead of appending "/prescripto" to the
    // URI, so connection strings with options (e.g. ?authSource=admin for an
    // authenticated MongoDB container) keep working.
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: "prescripto",
      serverSelectionTimeoutMS: 5000,
    });
  } catch (err) {
    // Don't let a failed initial DB connection crash the whole process with an
    // unhandled promise rejection; log it and let mongoose keep retrying.
    console.error("Initial MongoDB connection failed:", err?.message);
  }
};

export default connectDB;
