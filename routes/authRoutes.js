const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Configuración CORS (similar a otros módulos)
router.use((req, res, next) => {
    res.header(
        "Access-Control-Allow-Headers",
        "x-access-token, Origin, Content-Type, Accept"
    );
    next();
});

// Rutas de autenticación
router.post('/signin', authController.signin);
router.post('/signup', authController.signup);

module.exports = router;