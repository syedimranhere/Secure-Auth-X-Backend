import { Apierror } from "../utils/ErrorApi.js";
import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/AsyncHandler.js";
import { uploadcloud } from "../utils/Cloudinary.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import {
  isValidUsername,
  isValidPassword,
} from "../utils/credentialValidator.js";
import { sendEmail } from "../utils/Mailer.js";

const options = {
  httpOnly: true,
  secure: true,
  sameSite: "None", // THIS IS MANDATORY FOR CROSS-ORIGIN COOKIES!
};
export const generateAccessAndRefreshTokens = async (userId) => {
  const userDoc = await User.findById(userId)
    // 🧠 Don’t select out -refreshToken if you're about to update it
    .select("-password");
  if (!userDoc) {
    throw new Apierror(404, "User not found ❗");
  }
  //user object itself has methods ( of passcheck and tokens)
  const accessToken = await userDoc.generateAccessToken();
  const refreshToken = await userDoc.generateRefreshToken();
  //but we want refresh token to be stored in DB
  userDoc.refreshToken = refreshToken;
  //also save it, as we are updating the user document ( take time )
  await userDoc.save();

  //its better to have options in a single object

  return { accessToken, refreshToken };
};

// REGISTER USER
export const RegisterUser = asyncHandler(async (req, res) => {
  const { Username, Email, Password, Fullname } = req.body;

  if (!Username || !Email || !Password || !Fullname) {
    return res.status(401).json({
      message: "All fields are required",
    });
  }

  if (!isValidUsername(Username)) {
    return res.status(402).json({
      message: "Username not valid",
    });
  }
  if (!isValidPassword(Password)) {
    return res.status(403).json({
      message: "Weak Password",
    });
  }
  const existingUser = await User.findOne({
    $or: [{ username: Username }, { email: Email }],
  });

  if (existingUser) {
    return res.status(404).json({
      message: "User with username/email exists",
    });
  }
  // now take images and coverImage

  const AvatarImagePath = req.files?.Avatar?.[0]?.path || null;
  const CoverImagePath = req.files?.CoverImage?.[0]?.path || null;

  //this returns an Obj
  let UploadAvatar = null;
  if (AvatarImagePath != null) {
    UploadAvatar = await uploadcloud(AvatarImagePath);
  }

  let UploadCover = null;
  if (CoverImagePath != null) {
    UploadCover = await uploadcloud(CoverImagePath);
  }

  const USER = await User.create({
    username: Username,
    email: Email,
    password: Password,
    fullname: Fullname,
    avatar: UploadAvatar ? UploadAvatar.url : "",
    coverImage: UploadCover ? UploadCover.url : "",
  });
  return res
    .status(201)
    .json({ message: "User registered successfully", user: USER });
});

// LOGIN USER
export const LoginUser = asyncHandler(async (req, res) => {
  const { EmailorUsername, Password } = req.body;
  // const sessionId = uuidv4();

  if (!EmailorUsername || !Password) {
    throw new Apierror(400, "Email and Password are required");
  }

  const user = await User.findOne({
    $or: [{ email: EmailorUsername }, { username: EmailorUsername }],
  });

  if (!user) {
    throw new Apierror(401, "Invalid email/username or password");
  }

  const isPasswordValid = await user.isPassCorrect(Password);

  if (!isPasswordValid) {
    throw new Apierror(401, "Invalid email/username or password");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.connection.remoteAddress;
  const userAgent = req.headers["user-agent"];
  user.user_agent = userAgent;
  user.ip = ip;
  user.refreshToken = refreshToken; // Update the refresh token in the database
  await user.save();

  return res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .cookie("accessToken", accessToken, options)
    .json({
      success: true,
      user: {
        username: user.username,
        fullname: user.fullname,
        email: user.email,
      },
    });
});
// LOGOUT USER
// Clear his cookies
export const LogoutUser = asyncHandler(async (req, res) => {
  // Clear cookies first
  res.clearCookie("accessToken", options);
  res.clearCookie("refreshToken", options);

  if (!req.user || !req.user.id) {
    throw new Apierror(401, "Unauthorized: User not authenticated");
  }

  const USER = await User.findById(req.user.id);
  if (!USER) {
    throw new Apierror(400, "User not found");
  }
  USER.refreshToken = undefined;

  return res.status(200).json({ message: "Logged out successfully" });
});
//here we will be navigated if we click on forgetPassword

const generateOtp = () => {
  return Math.floor(1000 + Math.random() * 9000).toString();
};
export const SendOtp = asyncHandler(async (req, res) => {
  //take email and confirm that email

  const { email } = req.body;
  const USER = await User.findOne({ email });
  if (!USER) {
    throw new Apierror(401, "No user with such email");
  }

  // now if email is found send an email of otp
  const genOTP = generateOtp();
  const hashedOtp = await bcrypt.hash(genOTP, 10);
  const expiry = new Date(Date.now() + 1000 * 60 * 10);
  USER.otp = hashedOtp;
  USER.otpExpiry = expiry;

  await USER.save();

  //now send email via nodemailer call nodemailer
  await sendEmail({
    to: email,
    subject: "Your OTP For AuthX",
    html: `<h2 >Your OTP is ${genOTP}</h2><p>It expires in 10 minutes.</p>`,
  });
  return res
    .cookie("resetEmail", email, {
      httpOnly: true,
      secure: true,
      maxAge: 10 * 60 * 1000,
    })
    .status(200)
    .json({
      success: true,
      message: "OTP has been to your email successfully",
    });
});

export const VerifyOtp = asyncHandler(async (req, res) => {
  const { otp } = req.body;
  const email = req.resetEmail;
  const USER = await User.findOne({ email });
  if (!USER) {
    return res.status(401).json({ mess: "User Not Found" });
  }
  if (USER.otpExpiry < Date.now()) {
    return res.status(401).json({ mess: "OTP Expired" });
  }

  const userotp = USER.otp;
  const result = await bcrypt.compare(otp, userotp);

  if (!result) {
    return res.status(401).json({ mess: "OTP is Invalid" });
  }
  //now everything is good to go
  return res.status(200).json({
    success: true,
  });
});

export const newPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const email = req.resetEmail;
  const USER = await User.findOne({ email });
  if (!USER) {
    throw new Apierror(401, "No user with such email");
  }

  USER.password = password;
  await USER.save();
  return res.status(200).json({
    success: true,
  });
});
export const verifyAccess = async (req, res) => {
  const { accessToken } = req.cookies;

  if (!accessToken) return res.status(401).json({ message: "No access token" });

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN);
    if (!decoded || !decoded.id) {
      return res.status(403).json({ message: "Invalid access token" });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(403).json({ message: "Invalid access token" });
    }

    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.connection.remoteAddress;
    const userAgent = req.headers["user-agent"];
    if (user.ip !== ip || user.user_agent !== userAgent) {
      return res.status(403).json({ message: "Session not yours" });
    }
    // FIXED: Return actual user data instead of just a message
    res.status(200).json({
      success: true,
      user: {
        username: user.username,
        fullname: user.fullname,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(403).json({ message: "Invalid access token" });
  }
};
export const GetTokens = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN);
    if (!decoded || !decoded.id) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }
    if (user.refreshToken !== refreshToken) {
      return res
        .status(403)
        .json({ message: "Token reuse detected. Possible session hijack!" });
    }

    const { accessToken, refreshToken2 } = await generateAccessAndRefreshTokens(
      user._id
    );
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.connection.remoteAddress;
    const userAgent = req.headers["user-agent"];
    if (user.ip !== ip || user.user_agent !== userAgent) {
      return res.status(403).json({ message: "Session not yours" });
    }
    user.refreshToken = refreshToken2; // Update the refresh token in the database
    await user.save();
    res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken2, options)
      .json({ message: "Tokens Generated" });
  } catch (error) {
    res.status(403).json({ message: "Invalid Refresh Token" });
  }
};
