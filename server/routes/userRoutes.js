const express = require('express');
const { signUp, logIn, verifyToken, getUser, refreshToken, logout } = require('../controllers/userController');

const router = express();

router.post('/signup', signUp);
router.post('/login', logIn);
router.get('/user', verifyToken, getUser);
router.get('/refresh', refreshToken, verifyToken, getUser);
router.post('/logout', verifyToken, logout)
//verify token



module.exports = router;