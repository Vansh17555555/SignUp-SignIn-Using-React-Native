const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { jwtkey } = require('../keys');
const User = require('../models/User'); // Correct the path to your User model file
const router = express.Router();
const tokenget=require('../middleware/tokenget')
const cookieParser=require("cookie-parser");
router.use(cookieParser())
router.post('/signup',async (req, res) => {
    

    const { email, password } = req.body;

    try {
        const user = new User({ email, password }); // Use the User model to create a new user
        await user.save();
        const token = jwt.sign({ userId: user._id },jwtkey); // Create a new token with the user id
        res.send({ token });
    } catch (err) {
        if (err.code === 11000 && err.keyPattern && err.keyPattern.email === 1) {
            res.status(422).send('Email is already registered');
        } else {
            res.status(422).send(err.message);
        }
    }
    
   
});
router.post('/add-details', tokenget, async (req, res) => {
    const { phoneNumber, name } = req.body;
    const userId = req.user._id; // Authenticated user ID from tokenget middleware

    try {
        const user = await User.findByIdAndUpdate(userId, { phoneNumber, name }, { new: true });
        res.send(user);
    } catch (err) {
        res.status(500).send('Error adding details');
    }
});

// Route for modifying phone number and name
router.put('/modify-details', tokenget, async (req, res) => {
    const { phoneNumber, name } = req.body;
    const userId = req.user._id; // Authenticated user ID from tokenget middleware

    try {
        const user = await User.findByIdAndUpdate(userId, { phoneNumber, name }, { new: true });
        res.send(user);
    } catch (err) {
        res.status(500).send('Error modifying details');
    }
});



router.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(422).send('Must provide email and password');
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).send('Invalid email or password');
    }

    try {
        await user.comparePassword(password);
        const token = jwt.sign({ userId: user._id }, jwtkey);
        res.cookie('token', token, { httpOnly: true });
        res.send({ token });
    } catch (err) {
        res.status(404).send('Invalid email or password');
    }
});

module.exports = router;
