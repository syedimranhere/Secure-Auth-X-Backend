import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 5 mins
  max: 5, // Max 5 attempts per IP
  message: "❌ Too many attempts. Try again after 15 minutes.",
  standardHeaders: true,
  legacyHeaders: false,
});
