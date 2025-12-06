import { User } from '../models/User';

const signUp = async (req, res) => {
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
      confirmPassword,
      profileImage,
    } = req.body;

    // 1. Validate required fields
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
        .json({ message: 'All required fields must be filled' });
    }

    // 2. Validate password match
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    // 3. Check existing email
    const emailExists = await User.findOne({ email });
    if (emailExists) {
      return res.status(400).json({ message: 'Email is already registered' });
    }

    // 4. Check existing phone
    const phoneExists = await User.findOne({ phone });
    if (phoneExists) {
      return res.status(400).json({ message: 'Phone number already exists' });
    }

    // 5. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 6. Create user (do NOT save confirmPassword)
    const user = await User.create({
      firstName,
      lastName,
      email,
      phone,
      officailAddress,
      city,
      pincode,
      password: hashedPassword,
      profileImage,
    });
  } catch (error) {
    console.error('error having signup: ', error);
    return res.status(500).json({
      success: false,
      message: 'failed to signup',
      error: error.meassage,
    });
  }
};
