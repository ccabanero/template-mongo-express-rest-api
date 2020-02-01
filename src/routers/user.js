/* eslint-disable arrow-body-style */
const express = require('express');
const User = require('../models/user');
const auth = require('../middleware/authentication');

const router = new express.Router();

/**
 * Creates a User (i.e. sign up)
 */
router.post('/user', async (req, res) => {
  // Create the User.
  const user = new User(req.body);
  try {
    await user.save();
    return res.status(201).send({ // created
      user,
    });
  } catch (e) {
    return res.status(400).send(e); // bad request
  }
});

/**
 * Logs in a registered User - returning a JWT.
 */
router.post('/user/login', async (req, res) => {
  try {
    const user = await User.findByCredentials(req.body.email, req.body.password);
    const token = await user.generateAuthToken();
    return res.send({
      user,
      token,
    });
  } catch (e) {
    return res.status(401).send(); // unauthorized
  }
});

/**
 * Logs out a User - removing the request JWT associated with registered User.
 * Note: uses auth middleware for handling request authentication.
 */
router.post('/user/logout', auth, async (req, res) => {
  try {
    const logoutToken = req.header('Authorization').replace('Bearer ', '');
    req.user.tokens = req.user.tokens.filter((userToken) => {
      return userToken.token !== logoutToken;
    });
    await req.user.save();
    return res.send();
  } catch (e) {
    return res.status(500).send(); // internal server error
  }
});

/**
 * Logs out a User - removing ALL JWTs associated with registered User.
 */
router.post('/user/logoutAll', auth, async (req, res) => {
  try {
    req.user.tokens = [];
    await req.user.save();
    return res.send();
  } catch (e) {
    return res.status(500).send(); // internal server error
  }
});

/**
 * Fetches the authenticated users to get their own user info.
 */
router.get('/user/me', auth, async (req, res) => {
  return res.status(200).send({
    user: req.user,
  });
});

/**
 * Updates an authenticated User's info.
 */
router.patch('/user/me', auth, async (req, res) => {
  // Validate fields to be updated are allowed.
  const requestUpdates = Object.keys(req.body);
  const allowedUpdates = ['email', 'password'];
  const isValidOperation = requestUpdates.every((requestUpdate) => {
    return allowedUpdates.includes(requestUpdate);
  });
  if (!isValidOperation) {
    return res.status(400).send({
      error: 'Invalid update fields', // bad request
    });
  }

  // Update the User.
  try {
    requestUpdates.forEach((updateField) => {
      req.user[updateField] = req.body[updateField];
    });
    await req.user.save();
    return res.status(200).send(req.user); // ok
  } catch (e) {
    return res.status(500).send(e); // internal server error
  }
});

/**
 * Deletes an authenticated User.
 */
router.delete('/user/me', auth, async (req, res) => {
  // Delete the User.
  try {
    // Use the authenticated User (provided by auth) middelware.
    await req.user.remove();
    return res.status(200).send(req.user); // ok
  } catch (e) {
    return res.status(500).send(); // internal server error
  }
});

module.exports = router;
