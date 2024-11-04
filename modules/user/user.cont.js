const { User } = require('../../middleware/db');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      return res.status(400).send("All input is required");
    }

    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        { expiresIn: "1h" }
      );

      user.token = token;
      await user.save();

      res.status(200).json(user);
    } else {
      res.status(400).send("Invalid Credentials");
    }
  } catch (err) {
  }
};

exports.register = async (req, res) => {
  try {
    const { first_name, last_name, email, password } = req.body;

    if (!(email && password && first_name && last_name)) {
      res.status(400).send("All input is required");
    }

    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User already exists. Please login");
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      { expiresIn: "2h" }
    );

    user.token = token;

    res.status(201).json(user);
  } catch (err) {
  }
};

exports.updateUser = async (req, res) => {
  try {
    const { first_name, last_name } = req.body;
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).send("User data not found");
    }

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { first_name, last_name },
      { new: true }
    );

    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(400).send(error.message);
  }
};

exports.getUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).send("User data not found");
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(400).send(error.message);
  }
};
