import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
const userSchema = new Schema(
  {
    fullname: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      isLowercase: true,
      trim: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    avatar: {
      type: String,
    },
    coverImage: {
      type: String,
    },
    refreshToken: {
      type: String,
    },
    otp: {
      type: String,
    },
    otpExpiry: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// password validation

userSchema.pre("save", async function (params) {
  if (!this.isModified("password")) {
    return;
  }
  this.password = await bcrypt.hash(this.password, 14);
});

//now again we will define some methods
userSchema.methods.generateAccessToken = function () {
  return jwt.sign({ id: this._id }, process.env.ACCESS_TOKEN, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
  });
};
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign({ id: this._id }, process.env.REFRESH_TOKEN, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  });
};

userSchema.methods.isPassCorrect = async function (pass) {
  return await bcrypt.compare(pass, this.password);
};

export const User = mongoose.model("User", userSchema);
