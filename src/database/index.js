import mongoose from "mongoose";

const connectDB = async () => {
  try {
    const x = await mongoose.connect(`${process.env.MONGODB_URL}/AuraList`);
    console.log(x.connection.host);
  } catch (error) {
    console.log("Error connecting Database");
  }
};

export { connectDB };
