const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Ruta para registro de usuarios
router.post('/signup', authController.signup);

// Ruta para inicio de sesión
router.post('/signin', authController.signin);

module.exports = router;