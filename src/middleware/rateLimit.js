import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 5, // Max 5 attempts per IP
  message: "Too many attempts. Try again after a minute.",
  standardHeaders: true,
  legacyHeaders: false,
});
