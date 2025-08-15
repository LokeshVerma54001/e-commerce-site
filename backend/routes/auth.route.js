import express from 'express';
import { getProfile, login, logout, refereshToken, signup } from '../controllers/auth.controller.js';
import { protectRoute } from '../middleware/auth.middleware.js';

const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);
router.post('/referesh-token', refereshToken);
router.get('/profile',protectRoute ,getProfile);

export default router;