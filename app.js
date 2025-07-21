import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import mongoSanitize from "express-mongo-sanitize";

const app = express();
// server started
app.use(
  cors({
    origin: "*",
    credentials: true,
  })
);
app.use(express.json());

app.use(cookieParser({}));

import { UserRouter } from "./src/routes/user.routes.js";
app.use("/api/v1/user", UserRouter);
export { app };
