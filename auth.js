const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./users');
require('dotenv').config();

//Connect to MongoDB
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGODB_URL, { 
    useNewUrlParser: true
})
.then(() => console.log("Connected to DB"))
.catch((error) => console.log(error.message));

const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authorization header is missing' });
    }
    try {
      const decodedToken = jwt.verify(token, 'secret');
      req.user = decodedToken;
      next();
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };

//Signup endpoint
router.post('/signup', (req, res, next) => {
  // Check if user already exists
  User.findOne({ email: req.body.email })
    .exec()
    .then(user => {
      if (user) {
        return res.status(409).json({ message: 'Email already exists' });
      } else {
        // Create new user
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(500).json({ error: err });
          } else {
            const user = new User({
              email: req.body.email,
              password: hash
            });
            user.save()
              .then(result => {
                console.log(result);
                res.status(201).json({ message: 'User created' });
              })
              .catch(err => {
                console.log(err);
                res.status(500).json({ error: err });
              });
          }
        });
      }
    });
});

//Login endpoint
router.post('/login', (req, res, next) => {
  User.findOne({ email: req.body.email })
    .exec()
    .then(user => {
      if (!user) {
        return res.status(401).json({ message: 'Auth failed' });
      }
      bcrypt.compare(req.body.password, user.password, (err, result) => {
        if (err) {
          return res.status(401).json({ message: 'Auth failed' });
        }
        if (result) {
          const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET_KEY,
            { expiresIn: '1h' }
          );
          return res.status(200).json({ token: token });
        }
        res.status(401).json({ message: 'Auth failed' });
      });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({ error: err });
    });
});

//Profile endpoint
router.get('/profile', auth, (req, res, next) => {
  User.findById(req.userId)
    .exec()
    .then(user => {
      res.status(200).json({ email: user.email });
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({ error: err });
    });
});

module.exports = router;
