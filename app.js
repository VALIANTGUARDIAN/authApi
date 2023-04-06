const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const port = 8080;

// connection with mongoDB
mongoose
  .connect("mongodb://localhost:27017/testdb", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("DB connected"))
  .catch((err) => console.log("DB connection error", err));

// user schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

// user model
const User = mongoose.model("User", userSchema);
app.use(express.json());

// signup router
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(409).json({ error: "Email already exists" });
  }

  // hashing password
  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(password, salt);

  // create new user
  const newUser = new User({ email, password: hashedPassword });
  await newUser.save();
  res.send(newUser);

  const token = jwt.sign({ id: newUser._id });
  res.json({ token });
});

// signing router
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (!existingUser) {
    return res.status(401).json({ error: "Email or password is incorrect" });
  }

  const passwordMatch = await bcrypt.compare(password, existingUser.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: "Email or password is incorrect" });
  }

  const token = jwt.sign({ id: existingUser._id });

  res.json({ token });
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
