import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

const normalizeIdentifier = (value) => {
  const identifier = String(value).trim().toLowerCase();
  return identifier.includes('@') ? identifier : identifier.replace(/[\s().-]/g, '');
};

const PROFILE_FIELDS = {
  mentor: [
    'name', 'batch', 'degree', 'email', 'mobile', 'city', 'linkedin', 'role', 'org', 'industry',
    'experience', 'expertise', 'bio', 'tracks', 'pods', 'format', 'slots', 'timezone', 'problem',
    'consent',
  ],
  mentee: [
    'name', 'roll', 'dept', 'year', 'email', 'mobile', 'tutor', 'path', 'industries', 'help',
    'skills', 'project', 'format', 'frequency', 'consent',
  ],
  coordinator: [
    'name', 'staffId', 'designation', 'dept', 'email', 'mobile', 'programRole', 'depts', 'batch',
    'consent',
  ],
};

const REQUIRED_FIELDS = {
  mentor: ['name', 'batch', 'email', 'city', 'role', 'org', 'industry', 'experience', 'bio', 'tracks'],
  mentee: ['name', 'roll', 'dept', 'year', 'email', 'path', 'help'],
  coordinator: ['name', 'staffId', 'designation', 'dept', 'email', 'programRole'],
};
const hasRole = (role) => Object.hasOwn(PROFILE_FIELDS, role);
const toPublicUser = (user) => ({
  id: user.id,
  role: user.role,
  name: user.name,
  email: user.email,
  profile: user.profile,
});

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

export async function register(req, res, next) {
  try {
    const { role, profile: submittedProfile, password } = req.body;

    if (!hasRole(role)) {
      return res.status(400).json({ message: 'Choose a valid profile type.' });
    }
    if (!submittedProfile || typeof submittedProfile !== 'object' || Array.isArray(submittedProfile)) {
      return res.status(400).json({ message: 'Profile details are required.' });
    }
    if (typeof password !== 'string' || password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ message: 'Password must be at least 8 characters and no more than 72 bytes.' });
    }

    const profile = Object.fromEntries(
      Object.entries(submittedProfile)
        .filter(([key]) => PROFILE_FIELDS[role].includes(key))
        .map(([key, value]) => [
          key,
          typeof value === 'string' ? value.trim() : Array.isArray(value) ? value.map((item) => String(item).trim()) : value,
        ])
    );
    const missing = REQUIRED_FIELDS[role].filter((field) => {
      const value = profile[field];
      return Array.isArray(value) ? value.length === 0 : typeof value !== 'string' || value.length === 0;
    });

    if (missing.length > 0) {
      return res.status(400).json({ message: `Complete the required profile fields: ${missing.join(', ')}.` });
    }
    if (!isValidEmail(profile.email)) {
      return res.status(400).json({ message: 'Enter a valid email address.' });
    }
    if (profile.consent !== true) {
      return res.status(400).json({ message: 'Please confirm the profile consent before saving.' });
    }

    profile.email = profile.email.toLowerCase();
    const loginIdentifiers = [normalizeIdentifier(profile.email)];
    if (role === 'mentor' && profile.mobile) loginIdentifiers.push(normalizeIdentifier(profile.mobile));
    if (role === 'mentee') loginIdentifiers.push(normalizeIdentifier(profile.roll));
    if (role === 'coordinator') loginIdentifiers.push(normalizeIdentifier(profile.staffId));

    const user = await User.create({
      role,
      name: profile.name,
      email: profile.email,
      loginIdentifiers,
      passwordHash: await bcrypt.hash(password, 12),
      profile,
    });

    return res.status(201).json({
      message: 'Profile saved. You can now sign in.',
      user: { id: user.id, role: user.role, name: user.name, email: user.email },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ message: 'An account already exists with that email or sign-in ID.' });
    }
    return next(error);
  }
}

export async function login(req, res, next) {
  try {
    const { role, identifier, password, remember } = req.body;
    if (!hasRole(role) || typeof identifier !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Enter your sign-in details and choose your profile type.' });
    }

    const user = await User.findOne({
      role,
      loginIdentifiers: normalizeIdentifier(identifier),
    }).select('+passwordHash');
    const passwordMatches = user ? await bcrypt.compare(password, user.passwordHash) : false;
    if (!passwordMatches) {
      return res.status(401).json({ message: 'The profile type, sign-in ID or password is incorrect.' });
    }

    const persistent = remember === true;
    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: persistent ? '30d' : '1d' }
    );
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/auth',
    };
    if (persistent) cookieOptions.maxAge = 30 * 24 * 60 * 60 * 1000;
    res.cookie('mentorshipSession', token, cookieOptions);

    return res.json({
      user: toPublicUser(user),
    });
  } catch (error) {
    return next(error);
  }
}

export async function currentUser(req, res, next) {
  try {
    const user = await User.findById(req.auth.userId);
    if (!user || user.role !== req.auth.role) {
      res.clearCookie('mentorshipSession', { path: '/api/auth' });
      return res.status(401).json({ message: 'Your sign-in session has expired. Please sign in again.' });
    }

    return res.json({
      user: toPublicUser(user),
    });
  } catch (error) {
    return next(error);
  }
}

export function logout(_req, res) {
  res.clearCookie('mentorshipSession', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/api/auth',
  });
  return res.json({ message: 'Signed out.' });
}
