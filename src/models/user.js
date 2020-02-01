/* eslint-disable no-use-before-define */
/* eslint-disable func-names */
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

/**
 * Define the schema for User.
 */
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    unique: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error('Email is invalid');
      }
    },
  },
  password: {
    type: String,
    required: true,
    trim: true,
    minlength: 7,
    validate(value) {
      if (value.toLowerCase().includes('password')) {
        throw new Error('Password cannot contain the word password');
      }
    },
  },
  tokens: [{
    token: {
      type: String,
      required: true,
    },
  }],
  isAdmin: {
    type: Boolean,
    required: true,
    default: false,
  },
});

/**
 * Static method that finds the user in MongoDB.
 */
userSchema.statics.findByCredentials = async (email, password) => {
  const user = await User.findOne({ email });
  if (!user) {
    throw new Error('Unable to login');
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new Error('Unable to login');
  }
  return user;
};

/**
 * Instance method for creating JWT and saving to the db.
 */
userSchema.methods.generateAuthToken = async function () {
  const user = this;
  const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);
  user.tokens = user.tokens.concat({ token });
  await user.save();
  return token;
};

/**
 * Instance method for getting a User instance's public profile properties (provided by .toJSON)
 */
userSchema.methods.toJSON = function () {
  const user = this;
  const userObject = user.toObject();
  delete userObject.password;
  delete userObject.tokens;
  delete userObject.isAdmin;
  return userObject;
};

/**
 * Middle-ware method to hash the plain text password before calling the Mongoose .save() method.
 */
userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, 8);
  }
  next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
