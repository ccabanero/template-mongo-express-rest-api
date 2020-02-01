const jwt = require('jsonwebtoken');
const User = require('../models/user');

const auth = async (req, res, next) => {
  try {
    // Get token from request header.
    const token = req.header('Authorization').replace('Bearer ', '');

    // Check that the token in the request is associated with a User in the database.
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

    // Handle authentication failure (no User found associated with the token)
    if (!user) {
      throw new Error(); // sends to catch
    }

    // Pass route handler the authenticated user and token (reduce look-up)
    req.user = user;

    // Allow route handlers to proceed.
    next();
  } catch (e) {
    res.status(401).send({
      error: 'Please authenticate.',
    });
  }
};

module.exports = auth;
