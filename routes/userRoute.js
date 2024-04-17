const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const multer = require("multer");
const path = require("path");

router.use(express.json());

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
      cb(null, path.join(__dirname, "../public/postImages"));
    }
  },
  filename: function (req, file, cb) {
    const name = Date.now() + "-" + file.originalname;
    cb(null, name);
  },
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
});

const {
  registerValidator,
  sendMailVerificationValidator,
  passwordResetValidator,
  loginValidator,
  updateProfileValidator,
  otpMailValidator,
  verifyOtpValidator,
} = require("../helpers/validation");

const auth = require("../middleware/auth");

router.post(
  "/register",
  upload.single("image"),
  registerValidator,
  (req, res) => {
    try {
      userController.userRegister(req, res);
    } catch (error) {
      console.error("Error during user registration:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

router.post(
  "/send-mail-verification",
  sendMailVerificationValidator,
  userController.sendMailVerification
);

router.post(
  "/forgot-password",
  passwordResetValidator,
  userController.forgotPassword
);

router.post("/login", loginValidator, userController.loginUser);
router.get("/profile", auth, userController.userProfile);
router.post(
  "/update-profile",
  auth,
  upload.single("image"),
  updateProfileValidator,
  userController.updateProfile
);
router.get("/refresh-token", auth, userController.refreshToken);

router.get("/logout", auth, userController.logout);

//otp Mail Validator
router.post("/send-otp", otpMailValidator, userController.sendOtp);
router.post("/verify-otp", verifyOtpValidator, userController.verifyOtp);
module.exports = router;
