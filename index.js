import dotenv from "dotenv";
import { app } from "./app.js";
import { connectDB } from "./src/database/index.js";

// load .env
dotenv.config();

const PORT = process.env.PORT || 7000;

connectDB()
  .then(() => {
    console.log("✅ MongoDB Connected Successfully");
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB Connection Failed:", err);
    process.exit(1); // optional: crash the app if DB fails
  });
