import dotenv from 'dotenv';
dotenv.config();
import { Admin } from '../model/Admin.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const signUp = async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone, bio } = req.body;

    // console.log(req.body);

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'all fileds is required',
      });
    }

    const checkUserExist = await Admin.findOne({ email });

    if (checkUserExist) {
      return res.status(400).json({
        success: false,
        message: `admin already present !!`,
      });
    }

    //hashed password
    const hashedPassword = await bcrypt.hash(password, 10);

    const admin = await Admin.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      // profileImage: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
      phone: phone || null,
      bio: bio || 'Administrator',
      profileImage: null,
    });

    return res.status(201).json({
      success: true,
      message: 'SignUp  successfully',
      data: admin,
    });
  } catch (error) {
    console.error('Error while signup.', error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'email and password is required !',
      });
    }

    const user = await Admin.findOne({ email: email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found!',
      });
    }

    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign(
        {
          id: user._id,
          email: user.email,
          name: user.firstName,
        },
        process.env.JWT_SECRET_KEY,
        {
          expiresIn: '24h',
        }
      );

      // user.token = token;
      user.password = undefined;

      // SECURE cookie options
      const options = {
        expires: new Date(Date.now() + 48 * 60 * 60 * 1000), // 48 hours
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      };

      res.cookie('token', token, options).status(200).json({
        success: true,
        // token,
        user,
        message: `User Login Success`,
      });
    } else {
      return res.status(401).json({
        success: false,
        message: `Password is incorrect`,
      });
    }
  } catch (error) {
    console.error('Error in login', error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

const forgatePassword = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = Admin.findOne({ email: email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found !!',
      });
    }

    const result = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);

    // (async () => {
    //   try {
    //     await mailSender();
    //   } catch (err) {
    //     console.error('error sending mail', err);
    //   }
    // })();

    return res.status(201).json({
      success: false,
      message: 'Password changed successfully',
    });
  } catch (error) {
    console.error('Error in password change', error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const verifyAuth = async (req, res) => {
  try {
    // Get token from cookie
    const token = req.cookies.token;

    // console.log('token --> ', token);
    // console.log('req --> ', req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated',
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    // Get user from database
    const user = await Admin.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Return user data
    res.status(200).json({
      success: true,
      user,
      message: 'Authenticated',
    });
  } catch (error) {
    console.error('Error in verifyAuth:', error);
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token',
    });
  }
};

// Logout controller
export const logout = async (req, res) => {
  try {
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

export const changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmNewPassword } = req.body;
    const userId = req.user?._id;

    //  Basic validation
    if (!oldPassword || !newPassword || !confirmNewPassword) {
      return res.status(400).json({
        success: false,
        message: 'All password fields are required!',
      });
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({
        success: false,
        message: 'New password and confirm password do not match!',
      });
    }

    // Find user and include the password field
    const user = await Admin.findById(userId).select('+password');
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: 'User not found' });
    }

    // Verify if the old password is correct
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'The old password you entered is incorrect.',
      });
    }

    // 4. Update password
    // Note: If you have a 'pre-save' hook in your model that hashes passwords,
    // just assign it. Otherwise, hash it manually here.
    user.password = newPassword;
    await user.save();

    return res.status(200).json({
      success: true,
      message: 'Password updated successfully!',
    });
  } catch (error) {
    console.error('Failed to change the password:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const userId = req.user?._id;
    const { firstName, lastName, profileImage } = req.body;

    // 1. Find user and update
    // { new: true } returns the document AFTER the update
    // { runValidators: true } ensures the new data follows your schema rules
    const updatedAdmin = await Admin.findByIdAndUpdate(
      userId,
      {
        $set: {
          firstName,
          lastName,
          profileImage,
        },
      },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedAdmin) {
      return res.status(404).json({
        success: false,
        message: 'Admin not found',
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: updatedAdmin,
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Internal Server Error',
    });
  }
};
