import { Router } from "express";
import { upload } from "../middleware/MulterMiddleware.js";
import {
  RegisterUser,
  LoginUser,
  LogoutUser,
  GetTokens,
  SendOtp,
  refreshToken,
  VerifyOtp,
  get_tokens,
  newPassword,
} from "../controllers/user.controller.js";
import { isAuthenticated } from "../middleware/Authentication.js";
import { extractResetEmail } from "../middleware/getemail.js";
import { loginLimiter } from "../middleware/rateLimit.js";
const UserRouter = Router();

UserRouter.post(
  "/register",
  upload.fields([
    { name: "Avatar", maxCount: 1 },
    { name: "CoverImage", maxCount: 1 },
  ]),
  RegisterUser
);
UserRouter.post("/login", loginLimiter, LoginUser);
UserRouter.post("/logout", isAuthenticated, LogoutUser);
UserRouter.post("/refresh", GetTokens);
// abovs cant have isAuth, because no acces cookies to confirm, if refreshToken also expires we head to LOGIN
UserRouter.post("/send-otp", SendOtp);
// now we will use middleware first to extract the email,which we sent in form of cookies inside
UserRouter.post("/verifyotp", extractResetEmail, VerifyOtp);
UserRouter.post("/reset-password", extractResetEmail, newPassword);
UserRouter.get("/verify-token", isAuthenticated, refreshToken);
UserRouter.get("/get-token", isAuthenticated, get_tokens);

export { UserRouter };
