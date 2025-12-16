import express from 'express';
import {
  signup,
  login,
  verifyAuth,
  logout,
} from '../controllers/userController.js';
import { authenticateUser } from '../middlewares/auth.js';

const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);

router.post('/logout', logout);
router.get('/verify', verifyAuth);

export default router;
