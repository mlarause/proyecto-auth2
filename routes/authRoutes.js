const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifySignUp } = require('../middlewares');

// Middleware de diagnóstico
router.use((req, res, next) => {
    console.log('\n[AuthRoutes] Petición recibida:', {
        method: req.method,
        path: req.path,
        headers: {
            authorization: req.headers.authorization ? '***' : 'NO',
            'x-access-token': req.headers['x-access-token'] ? '***' : 'NO'
        }
    });
    next();
});

// Ruta de login
router.post('/signin', authController.signin);

// Ruta de registro CORREGIDA (sin verifyToken)
router.post('/signup', 
    (req, res, next) => {
        console.log('[AuthRoutes] Middleware de verificación de registro');
        next();
    },
    verifySignUp.checkDuplicateUsernameOrEmail,
    verifySignUp.checkRolesExisted,
    authController.signup
);

module.exports = router;