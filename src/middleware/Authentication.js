import jwt from "jsonwebtoken";
import { Apierror } from "../utils/ErrorApi.js";
import { asyncHandler } from "../utils/AsyncHandler.js";
import { User } from "../models/user.model.js";
export const isAuthenticated = asyncHandler(async (req, next) => {
  try {
    const cookieToken = req.cookies?.accessToken;
    if (!cookieToken) {
      throw new Apierror(401, "You are not authenticated ❗");
    }
    const isLegit = jwt.verify(cookieToken, process.env.ACCESS_TOKEN);
    if (!isLegit) {
      throw new Apierror(401, "Invalid token ❗");
    }
    const user = await User
      //is legit has our payload
      .findById(isLegit.id)
      .select("-password -refreshToken");

    if (!user) {
      throw new Apierror(401, "User not found ❗");
    }
    req.user = user;
    next();
  } catch (error) {
    throw new Apierror(401, error.message || "AUTHENTICATION FAILED ❗");
  }
});
