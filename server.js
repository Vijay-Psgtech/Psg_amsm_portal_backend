import connectDB from './config/db.js';
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import authRoutes from './routes/authRoutes.js';

dotenv.config();

const app = express();

const allowedOrigins = (process.env.CLIENT_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim());

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      const error = new Error('Origin is not allowed by CORS.');
      error.status = 403;
      callback(error);
    },
    credentials: true,
  })
);
app.use(helmet());
app.use(morgan('dev'));
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use('/api/auth', authRoutes);

app.use((_req, res) => {
  res.status(404).json({ message: 'Route not found.' });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({
    message: err.status ? err.message : 'Internal server error.',
  });
});

const PORT = process.env.PORT || 5000;

try {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be set to a value of at least 32 characters.');
  }
  await connectDB();
  app.listen(PORT, () => {
    console.log(`PSG Mentorship API running on port ${PORT}`);
  });
} catch (error) {
  console.error('Unable to start the API:', error.message);
  process.exitCode = 1;
}
