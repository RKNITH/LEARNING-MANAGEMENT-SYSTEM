const User = require("../../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const registerUser = async (req, res) => {
  try {
    const { userName, userEmail, password, role } = req.body;

    // Validate required fields
    if (!userName || !userEmail || !password) {
      return res.status(400).json({
        success: false,
        message: "User name, email, and password are required",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ userEmail }, { userName }],
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User name or user email already exists",
      });
    }

    // Assign default role if not provided
    const userRole = role || "user";

    // Hash the password
    const hashPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      userName,
      userEmail,
      role: userRole,
      password: hashPassword,
    });

    // Save user to the database
    await newUser.save();

    // Respond with success message
    return res.status(201).json({
      success: true,
      message: "User registered successfully!",
    });
  } catch (error) {
    console.error("Error during user registration:", error);
    return res.status(500).json({
      success: false,
      message: "An error occurred while registering. Please try again later.",
    });
  }
};

const loginUser = async (req, res) => {
  const { userEmail, password } = req.body;

  try {
    // Check if the user exists in the database
    const checkUser = await User.findOne({ userEmail });
    if (!checkUser || !(await bcrypt.compare(password, checkUser.password))) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Generate JWT with the correct secret from environment variables
    const accessToken = jwt.sign(
      {
        _id: checkUser._id,
        userName: checkUser.userName,
        userEmail: checkUser.userEmail,
        role: checkUser.role,
      },
      process.env.JWT_SECRET, // Use the environment variable for JWT secret
      { expiresIn: "120m" }
    );

    // Send the access token and user data back to the client
    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      data: {
        accessToken,
        user: {
          _id: checkUser._id,
          userName: checkUser.userName,
          userEmail: checkUser.userEmail,
          role: checkUser.role,
        },
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred during login. Please try again later.",
    });
  }
};

module.exports = { registerUser, loginUser };
