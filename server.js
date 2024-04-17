const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
mongoose.connect(
  "mongodb+srv://adarshkumar3088877:rNxHT8BEgh4qwnvS@cluster0.bhnyw6p.mongodb.net/jwt-auth-app?retryWrites=true&w=majority"
);

const app = express();

app.set("view engine", "ejs");
app.set("views", "./views");

const port = process.env.SERVER_PORT | 3000;

const userRoute = require("./routes/userRoute");
app.use("/api/v1", userRoute);

const authRoute = require("./routes/authRoute");
app.use("/", authRoute);

app.listen(port, function () {
  console.log(`Server Listen on port` + port);
});
