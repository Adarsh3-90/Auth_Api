const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const { validationResult } = require("express-validator");
const mailer = require("../helpers/mailer");
const randomstring = require("randomstring");
const PasswordReset = require("../models/passwordReset");
const jwt = require("jsonwebtoken");
const path = require("path");
const { deleteFile } = require("../helpers/deleteFile");
const Blacklist = require("../models/blacklist");
const Otp = require("../models/otp");
const { timeStamp } = require("console");
const {
  oneMinuteExpiry,
  threeMinuteExpiry,
} = require("../helpers/otpValidate");

//WRITE THE aPI OF USER REGISTER API

const userRegister = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }
    const { name, email, mobile, password, image } = req.body;

    const isExists = await User.findOne({ email });

    if (isExists) {
      return res.status(400).json({
        success: false,
        msg: "Email Already Exists",
      });
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      mobile,
      password: hashPassword,
      image: "public/postImages/" + req.file.filename,
    });

    const userData = await user.save();

    const msg =
      "<P>Hii " +
      name +
      ', Please <a href="http://127.0.0.1:3000/mail-verification?id=' +
      userData._id +
      '" >Verify</a> your Mail</P>';

    mailer.sendMail(email, "Mail Verification", msg);

    return res.status(200).json({
      success: true,
      msg: "Registered Successfully",
      user: userData,
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//for mail verification code

const mailverification = async (req, res) => {
  try {
    if (req.query.id == undefined) {
      return res.render("404");
    }

    const userData = await User.findOne({ _id: req.query.id });

    if (userData) {
      if (userData.is_verified == 1) {
        return res.render("mail-verification", {
          message: "Your Mail Allready Verified Successfully",
        });
      }
      await User.findByIdAndUpdate(
        { _id: req.query.id },
        {
          $set: {
            is_verified: 1,
          },
        }
      );

      return res.render("mail-verification", {
        message: "Mail has been verified successfully!",
      });
    } else {
      return res.render("mail-verification", { message: "User not Found!" });
    }
  } catch (error) {
    console.log(error.message);
    return res.render("404");
  }
};

//create api for send mail verification Link

const sendMailVerification = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }

    const { email } = req.body;

    const userData = await User.findOne({ email });
    if (!userData) {
      return res.status(400).json({
        success: false,
        msg: "Email doesn't exists!",
      });
    }

    if (userData.is_verified == 1) {
      return res.status(200).json({
        success: false,
        msg: userData.email + "mail is already verified!",
      });
    }

    const msg =
      "<P>Hii " +
      userData.name +
      ', Please <a href="http://127.0.0.1:3000/mail-verification?id=' +
      userData._id +
      '" >Verify</a> your Mail</P>';

    mailer.sendMail(userData.email, "Mail Verification", msg);

    return res.status(200).json({
      success: true,
      msg: "Verification Link sent to your mail,please checked",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//Write the Api of Forgot Password

const forgotPassword = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }

    const { email } = req.body;

    const userData = await User.findOne({ email });
    if (!userData) {
      return res.status(400).json({
        success: false,
        msg: "Email doesn't exists!",
      });
    }

    const randomString = randomstring.generate();

    const msg =
      "<p>Hii " +
      userData.name +
      ',Please click <a href="http://127.0.0.1:3000/reset-password?token=' +
      randomString +
      '">here</a>To Reset your Password </p>';
    await PasswordReset.deleteMany({ user_id: userData._id });

    const passwordReset = new PasswordReset({
      user_id: userData._id,
      token: randomString,
    });

    await passwordReset.save();
    mailer.sendMail(userData.email, "Reset Password", msg);

    return res.status(201).json({
      success: true,
      msg: "Reset Password Link send to your mail, Please check !",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//write the API for REset password

const resetPassword = async (req, res) => {
  try {
    if (req.query.token == undefined) {
      return res.render("404");
    }

    const resetData = await PasswordReset.findOne({ token: req.query.token });

    if (!resetData) {
      return res.render("404");
    }

    return res.render("reset-password", { resetData });
  } catch (error) {
    return res.render("404");
  }
};

//write the API of Update Password

const updatePassword = async (req, res) => {
  try {
    const { user_id, password, c_password } = req.body;
    const resetData = await PasswordReset.findOne({ user_id });

    if (password != c_password) {
      return res.render("reset-password", {
        resetData,
        error: "Confirm Password is not Matching!",
      });
    }

    const hashedPassword = await bcrypt.hash(c_password, 10);

    await User.findByIdAndUpdate(
      { _id: user_id },
      {
        $set: {
          password: hashedPassword,
        },
      }
    );
    await PasswordReset.deleteMany({ user_id });

    return res.redirect("/reset-success");
  } catch (error) {
    return res.render("404");
  }
};

const resetSuccess = async (req, res) => {
  try {
    return res.render("reset-success");
  } catch (error) {
    return res.render("404");
  }
};

//write the API for Login User

const generateAccessToken = async (user) => {
  const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "2h",
  });
  return token;
};

const generateRefreshToken = async (user) => {
  const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "4h",
  });
  return token;
};

const loginUser = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }
    const { email, password } = req.body;
    const userData = await User.findOne({ email });

    if (!userData) {
      return res.status(401).json({
        success: false,
        msg: "Email And Password is Incorrect !",
      });
    }

    const passwordMatch = await bcrypt.compare(password, userData.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        msg: "Email And Password is Incorrect !",
      });
    }

    if (userData.is_verified == 0) {
      return res.status(401).json({
        success: false,
        msg: "Please Verify your Account!",
      });
    }
    const accessToken = await generateAccessToken({ user: userData });
    const refreshToken = await generateRefreshToken({ user: userData });
    return res.status(200).json({
      success: true,
      msg: "Login Successfully!",
      user: userData,
      accessToken: accessToken,
      refreshToken: refreshToken,
      tokenType: "Bearer",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

// Write the Api for UserProfile

const userProfile = async (req, res) => {
  try {
    // console.log("gasdg");
    const userData = req.user.user;

    return res.status(400).json({
      success: true,
      msg: "User Profile Data !",
      data: userData,
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//write the API of Update Profile

const updateProfile = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }

    const { name, mobile } = req.body;

    const data = {
      name,
      mobile,
    };

    const user_id = req.user.user._id;

    if (req.file !== undefined) {
      data.image = "image/" + req.file.filename;
      const oldUser = await User.findOne({ _id: user_id });

      const oldFilePath = path.join(__dirname, "../public" + oldUser.image);

      await deleteFile(oldFilePath);
    }

    const userData = await User.findByIdAndUpdate(
      { _id: user_id },
      {
        $set: data,
      },
      { new: true }
    );

    return res.status(200).json({
      success: true,
      msg: "User Updated Successfully",
      user: userData,
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//write the Api for refreshToken

const refreshToken = async (req, res) => {
  try {
    const userId = req.user.user._id;

    const userData = await User.findOne({ _id: userId });
    const accessToken = await generateAccessToken({ user: userData });
    const refreshToken = await generateRefreshToken({ user: userData });

    return res.status(200).json({
      success: true,
      msg: "Token Rereshed!",
      accessToken: accessToken,
      refreshToken: refreshToken,
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//write the API for Logout API
const logout = async (req, res) => {
  try {
    const token =
      req.body.token || req.query.token || req.headers["authorization"];

    const bearerToken = token.split(" ")[1];

    const newBlacklist = new Blacklist({
      token: bearerToken,
    });

    await newBlacklist.save();

    res.setHeader("Clear-Site-Data", '"cookies","storage"');

    return res.status(200).json({
      success: true,
      msg: "You Are Logged Out!",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//write the Api for sendotp

const generateRandom4Digit = async () => {
  return Math.floor(1000 + Math.random() * 9000);
};

const sendOtp = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }

    const { email } = req.body;

    const userData = await User.findOne({ email });

    if (!userData) {
      return res.status(400).json({
        success: false,
        msg: "Email doesno't exists",
      });
    }

    if (userData.is_verified == 1) {
      return res.status(400).json({
        success: false,
        msg: userData.email + "mail is already verified!",
      });
    }

    const g_otp = await generateRandom4Digit();

    const oldOtpData = await Otp.findOne({ user_id: userData._id });

    if (oldOtpData) {
      const sendNextOtp = await oneMinuteExpiry(oldOtpData.timestamp);

      if (!sendNextOtp) {
        return res.status(400).json({
          success: false,
          msg: "Pls try after some times!",
        });
      }
    }
    const cDate = new Date();

    await Otp.findOneAndUpdate(
      { user_id: userData._id },
      { otp: g_otp, timestamp: new Date(cDate.getTime()) },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    const msg =
      "<p> Hii <b>" + userData.name + "</b>, </br> <h4>" + g_otp + "</h4></p>";

    mailer.sendMail(userData.email, "Otp Verification", msg);

    return res.status(200).json({
      success: true,
      msg: "Otp has been sent to your Mail, Please check!",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

//WRITE THE aPI FOR VERIFY oTP
const verifyOtp = async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        msg: "Errors",
        errors: errors.array(),
      });
    }

    const { user_id, otp } = req.body;

    const otpData = await Otp.findOne({
      user_id,
      otp,
    });

    if (!otpData) {
      return res.status(400).json({
        success: false,
        msg: "You entered Wrong OTP!",
      });
    }
    const isOtpExpired = await threeMinuteExpiry(otpData.timestamp);

    if (isOtpExpired) {
      return res.status(400).json({
        success: false,
        msg: "Your OTP has been Expired!",
      });
    }

    await User.findByIdAndUpdate(
      { _id: user_id },
      {
        $set: {
          is_verified: 1,
        },
      }
    );

    return res.status(200).json({
      success: true,
      msg: "Account Verified Successfully!",
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      msg: error.message,
    });
  }
};

module.exports = {
  userRegister,
  mailverification,
  sendMailVerification,
  forgotPassword,
  resetPassword,
  updatePassword,
  resetSuccess,
  loginUser,
  userProfile,
  updateProfile,
  refreshToken,
  logout,
  sendOtp,
  verifyOtp,
};
