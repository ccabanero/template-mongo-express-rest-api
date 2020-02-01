
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const User = require('../../src/models/user');

// Creates test user to add to test database.
const testUserId = new mongoose.Types.ObjectId();
const testUser = {
  _id: testUserId,
  email: 'userone@email.com',
  password: 'p@ssWURD!',
  tokens: [{
    token: jwt.sign({ _id: testUserId }, process.env.JWT_SECRET),
  }],
};

// Create a second test user for authenticating sale requests
const testUser2Id = new mongoose.Types.ObjectId();
const testUser2 = {
  _id: testUserId,
  email: 'usertwo@email.com',
  password: 'p@ssWURD!',
  tokens: [{
    token: jwt.sign({ _id: testUser2Id }, process.env.JWT_SECRET),
  }],
};

/**
 * Set up test database with test user and test sale.  Remove any previous users.
 */
const setupTestUserInDatabase = async () => {
  await User.deleteMany();
  await new User(testUser).save();
};

module.exports = {
  testUser,
  testUser2,
  setupTestUserInDatabase,
};
