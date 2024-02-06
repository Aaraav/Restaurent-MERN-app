const express = require('express');
const userModel = require('../models/userModel');
const foodModel = require('../models/foodModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const upload = require('../multer');

const secret = 'aaraav';
const router = express.Router();

router.get('/signup', function(req, res) {
   res.send('Signup');
});

router.post('/signup', async function(req, res) {
    const { username, email, password } = req.body;

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const newUser = new userModel({
        username: username,
        email: email,
        password: hashedPassword
    });

    try {
        await newUser.save();
        res.status(201).send('User registered successfully');
    } catch (error) {
        res.status(500).send('Error registering user');
    }
});

router.get('/done', verifyToken, function(req, res) {
    res.send('done');
});

router.post('/login', async function(req, res) {
    const { username, password } = req.body;

    try {
        const user = await userModel.findOne({ username: username });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const payload = {
            username: username,
            userId: user._id
        };

        const token = jwt.sign(payload,secret );
        console.log(token);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

function verifyToken(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(403).json({ message: 'Token is required' });
    }

    const tokenParts = token.split(' ');
    const bearerToken = tokenParts[1];

    jwt.verify(bearerToken, secret, (err, decoded) => {
        if (err) {
            console.error('Token verification error:', err);
            return res.status(401).json({ message: 'Token is invalid' });
        }
        req.user = decoded;
        console.log(req.user);
        next();
    });
}

router.post('/logout', function(req, res) {
    localStorage.removeItem('token');
});

router.get('/user', verifyToken, async function(req, res) {
    try {
        const username = req.user.username;
        console.log(username);

        const user = await userModel.findOne({ username });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ user });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/uploadfood', upload.single('file'), async (req, res) => {
    try {
        const { file, body: { aboutFood }, body: { price } } = req;

        const newFood = new foodModel({
            image: req.file.filename,
            description: aboutFood,
            price: price
        });

        console.log(newFood);
        await newFood.save();

        res.status(201).json({ message: 'Food item uploaded successfully' });
    } catch (error) {
        console.error('Error uploading food item:', error);
        res.status(500).json({ message: 'Error uploading food item' });
    }
});

router.get('/uploadfood', async (req, res) => {
    try {
        const food = await foodModel.find();
        if (!food || food.length === 0) {
            return res.status(404).json({ message: 'No uploaded food data available' });
        }

        res.status(200).json(food);
    } catch (error) {
        console.error('Error fetching uploaded food data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.get('/menu', verifyToken, (req, res) => {
    res.send(200);
});

module.exports = router;
