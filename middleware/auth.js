// const jwt = require("jsonwebtoken");
// const config = process.env;

// const verifyToken = async (req, res, next) => {
//   const token =
//     req.body.token || req.query.token || req.headers["authorization"];

//   if (!token) {
//     return res.status(403).json({
//       success: false,
//       msg: "A token is required for authentication",
//     });
//   }

//   try {
//     const bearerToken = token.split(" ")[1];
//     if (!bearerToken) throw "Invalid token format";

//     const decodeData = jwt.verify(bearerToken, config.ACCESS_TOKEN_SECRET);
//     req.user = decodeData;
//     next();
//   } catch (error) {
//     return res.status(403).json({
//       success: false,
//       msg: "Invalid token",
//     });
//   }

//   return next();
// };

// module.exports = verifyToken;

const jwt = require("jsonwebtoken");
const Blacklist = require("../models/blacklist");

const config = process.env;

const verifyToken = async (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["authorization"];

  if (!token) {
    return res.status(403).json({
      success: false,
      msg: "A token is required for authentication",
    });
  }

  try {
    const bearerToken = token.split(" ")[1];

    const blacklistedToken = await Blacklist.findOne({ token: bearerToken });

    if (blacklistedToken) {
      return res.status(400).json({
        success: false,
        msg: "This session has expired,please try again !",
      });
    }

    if (!bearerToken) throw "Invalid token format";

    const decodeData = jwt.verify(bearerToken, config.ACCESS_TOKEN_SECRET);
    req.user = decodeData;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      msg: "Invalid token",
      error: error.toString(),
    });
  }
};

module.exports = verifyToken;
