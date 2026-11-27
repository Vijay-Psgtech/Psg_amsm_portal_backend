import jwt from 'jsonwebtoken';

export default function authenticate(req, res, next) {
  const token = req.cookies?.mentorshipSession;
  if (!token) {
    return res.status(401).json({ message: 'Please sign in to continue.' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string' || typeof payload.role !== 'string') {
      return res.status(401).json({ message: 'Your sign-in session is invalid. Please sign in again.' });
    }
    req.auth = { userId: payload.sub, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ message: 'Your sign-in session has expired. Please sign in again.' });
  }
}
