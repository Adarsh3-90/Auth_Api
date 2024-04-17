const { check } = require("express-validator");

//register Validator

exports.registerValidator = [
  check("name", "Name is Required").not().isEmpty(),
  check("email", "Please include a valid Email").isEmail().normalizeEmail({
    gmail_remove_dots: true,
  }),
  check("mobile", "Mobile No Should be Contains 10 Digiit Number ").isLength({
    min: 10,
    max: 10,
  }),
  check(
    "password",
    "Password Must Be Greater than 6 character and contains at least one uppercase letter,one lowercase letter and one number and one special character"
  ).isStrongPassword({
    minLength: 6,
    minUppercase: 1,
    minLowercase: 1,
    minNumbers: 1,
  }),

  check("image")
    .custom((value, { req }) => {
      if (
        req.file.mimetype === "image/jpeg" ||
        req.file.mimetype === "image/png"
      ) {
        return true;
      } else {
        return false;
      }
    })
    .withMessage("Please Upload An Image Jpeg,PNG"),
];

//send mail Verification

exports.sendMailVerificationValidator = [
  check("email", "Please include a valid Email").isEmail().normalizeEmail({
    gmail_remove_dots: true,
  }),
];

exports.passwordResetValidator = [
  check("email", "Please include a valid Email").isEmail().normalizeEmail({
    gmail_remove_dots: true,
  }),
];

exports.loginValidator = [
  check("email", "Please include a valid Email").isEmail().normalizeEmail({
    gmail_remove_dots: true,
  }),
  check("password", "Password is required").not().isEmpty(),
];

//check the validation of update profile

exports.updateProfileValidator = [
  check("name", "Name is Required").not().isEmpty(),

  check("mobile", "Mobile No Should be Contains 10 Digiit Number ").isLength({
    min: 10,
    max: 10,
  }),
];

//check the validation of otp mailValidator

exports.otpMailValidator = [
  check("email", "Please include a valid Email").isEmail().normalizeEmail({
    gmail_remove_dots: true,
  }),
];

exports.verifyOtpValidator = [
  check("user_id", "User Id is required").not().isEmpty(),
  check("otp", "OTP is required").not().isEmpty(),
];
