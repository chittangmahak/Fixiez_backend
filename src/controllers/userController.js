import dotenv from 'dotenv';
dotenv.config();
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { User } from '../models/User.js';

const signToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

export const signup = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      officailAddress,
      city,
      pincode,
      password,
      profileImage,
    } = req.body;

    // basic validation
    if (
      !firstName ||
      !lastName ||
      !email ||
      !phone ||
      !city ||
      !pincode ||
      !password
    ) {
      return res
        .status(400)
        .json({ message: 'All required fields must be provided.' });
    }

    if (String(password).length < 6) {
      return res
        .status(400)
        .json({ message: 'Password must be at least 6 characters.' });
    }

    // check existing email
    const existing = await User.findOne({
      email: String(email).toLowerCase().trim(),
    });
    if (existing) {
      return res
        .status(409)
        .json({ message: 'Email already registered. Please login.' });
    }

    // hash password
    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      firstName: String(firstName).trim(),
      lastName: String(lastName).trim(),
      email: String(email).toLowerCase().trim(),
      phone: String(phone).trim(),
      officailAddress: officailAddress ? String(officailAddress).trim() : '',
      city: String(city).trim(),
      pincode: Number(pincode),
      password: hashed,
      profileImage: profileImage ? String(profileImage).trim() : '',
    });

    const token = signToken(user._id);

    // never send password
    const safeUser = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      phone: user.phone,
      officailAddress: user.officailAddress,
      city: user.city,
      pincode: user.pincode,
      profileImage: user.profileImage,
      createdAt: user.createdAt,
    };

    return res
      .status(201)
      .json({ message: 'Signup successful', user: safeUser, token });
  } catch (err) {
    // Handle mongoose unique error
    if (err?.code === 11000) {
      return res.status(409).json({ message: 'Email already exists.' });
    }
    console.error('Signup error:', err);
    return res.status(500).json({ message: 'Server error in signup.' });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: 'Email and password are required.' });
    }

    const user = await User.findOne({
      email: String(email).toLowerCase().trim(),
    });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const token = signToken(user._id);

    const safeUser = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      phone: user.phone,
      officailAddress: user.officailAddress,
      city: user.city,
      pincode: user.pincode,
      profileImage: user.profileImage,
      createdAt: user.createdAt,
    };

    return res
      .status(200)
      .json({ message: 'Login successful', user: safeUser, token });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error in login.' });
  }
};

//verify authentication controller
export const verifyAuth = async (req, res) => {
  try {
    const cookieToken = req.cookies?.token;

    const authHeader = req.headers.authorization;
    const bearerToken =
      authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : null;

    const token = cookieToken || bearerToken;

    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: 'Not authenticated' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: 'User not found' });
    }

    return res.status(200).json({
      success: true,
      user,
      message: 'Authenticated',
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token',
    });
  }
};

// Logout controller - Clear cookie
export const logout = async (req, res) => {
  try {
    // Clear the cookie
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('Error in logout:', error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
