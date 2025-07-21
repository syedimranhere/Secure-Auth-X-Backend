import nodemailer from "nodemailer";

export const sendEmail = async ({ to, subject, html} ) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });


  const mailOptions = {
    from: `"SecureAuth X" <${process.env.MAIL_USER}>`,
    to,
    subject,
    html, // you send full HTML string for design
  };

  await transporter.sendMail(mailOptions);
};1
