import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    role: {
      type: String,
      enum: ['mentor', 'mentee', 'coordinator'],
      required: true,
    },
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    loginIdentifiers: { type: [String], required: true },
    passwordHash: { type: String, required: true, select: false },
    profile: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: true }
);

userSchema.index({ role: 1, loginIdentifiers: 1 }, { unique: true });

export default mongoose.model('User', userSchema);
