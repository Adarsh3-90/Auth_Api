const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  post: process.env.SMTP_PORT,
  secure: false,
  requireTLS: true,

  auth: {
    user: process.env.SMTP_MAIL,
    pass: process.env.SMTP_PASSWORD,
  },
});

const sendMail = async (email, subject, content) => {
  try {
    var mailoption = {
      from: process.env.SMTP_MAIL,
      to: email,
      subject: subject,
      html: content,
    };
    transporter.sendMail(mailoption, (error, info) => {
      if (error) {
        console.log(error);
      }

      console.log("mail sent", info.messageId);
    });
  } catch (error) {
    console.log(error.message);
  }
};

module.exports = {
  sendMail,
};
