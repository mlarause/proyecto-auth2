const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifySignUp } = require('../middlewares');

// Importación con verificación
let verifyToken;
try {
    const authJwt = require('../middlewares/authJwt');
    verifyToken = authJwt.verifyToken;
    console.log('[AuthRoutes] verifyToken importado correctamente:', typeof verifyToken);
} catch (error) {
    console.error('[AuthRoutes] ERROR al importar verifyToken:', error);
    throw error;
}

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

// Ruta de login (sin protección)
router.post('/signin', authController.signin);

// Ruta de registro CORREGIDA (sin verifyToken, con middlewares de verificación de registro)
router.post('/signup', 
    (req, res, next) => {
        console.log('[AuthRoutes] Middleware de verificación de registro');
        next();
    },
    verifySignUp.checkDuplicateUsernameOrEmail,
    verifySignUp.checkRolesExisted,
    authController.signup
);

// Verificación final de rutas
console.log('[AuthRoutes] Rutas configuradas:', router.stack.map(layer => {
    return {
        path: layer.route?.path,
        methods: layer.route?.methods
    };
}));

module.exports = router;