import mongoose, { Document, Model, Schema } from 'mongoose';
import bcrypt from 'bcryptjs';

interface UserDocument extends Document {
  name: string;
  email: string;
  password: string;
  role: string;
  profilePicture: string;
  matchPassword(enteredPassword: string): Promise<boolean>;
}

interface UserModel extends Model<UserDocument> {}

const userSchema: Schema<UserDocument, UserModel> = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    profilePicture: {
      type: String,
      default:
        '',
    },
    // TODO: admin routes
    role: {
      type: String,
      default: 'user',
      enum: ['user', 'admin', 'superadmin'],
    }
  },
  {
    timestamps: true,
  }
);

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (
  enteredPassword: string
): Promise<boolean> {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Encrypt password using bcrypt
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

const User: Model<UserDocument> = mongoose.model<UserDocument, UserModel>(
  'User',
  userSchema
);

export default User;
