import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { currentUser, login, logout, register } from '../controllers/authController.js';
import authenticate from '../middleware/authenticate.js';

const router = Router();
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
});

router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.post('/logout', logout);
router.get('/me', authenticate, currentUser);

export default router;
