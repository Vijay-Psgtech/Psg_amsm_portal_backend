import connectDB from './config/db.js';
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
dotenv.config();

const app = express();

app.use(cors());
app.use(morgan('dev'));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


connectDB();

// ── CORS ─────────────────────────────────────────────────────────
const allowedOrigins = ['http://localhost:3000', 'https://your-frontend-domain.com'];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);


// ── Error handler ────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(err.status || 500).json({
    message: err.message || "Internal Server Error",
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 PSG Alumni Backend running on port ${PORT}`);
});
