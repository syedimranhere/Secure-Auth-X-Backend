import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(
  cors({
    origin: "https://secure-auth-x-frontend.vercel.app",
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));

app.use(cookieParser({}));

import { UserRouter } from "./src/routes/user.routes.js";
app.use("/api/v1/user", UserRouter);
export { app };
