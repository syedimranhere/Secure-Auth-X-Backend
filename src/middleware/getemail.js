// middleware/extractResetEmail.js
export const extractResetEmail = (req, res, next) => {
  const email = req.cookies?.resetEmail;
  if (!email) {
    return res.status(401).json({ success: false, message: "Session expired. Restart flow." });
  }
  req.resetEmail = email; // Attach to request
  next();
};
