const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { verifyToken } = require('../middlewares/authJwt');
const { checkRole } = require('../middlewares/role');

// Middleware de diagnóstico mejorado
router.use((req, res, next) => {
    console.log('\n=== DIAGNÓSTICO DE RUTA ===');
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    console.log('Headers completos:', JSON.stringify({
        ...req.headers,
        authorization: req.headers.authorization ? '***' + req.headers.authorization.slice(-8) : null,
        'x-access-token': req.headers['x-access-token'] ? '***' + req.headers['x-access-token'].slice(-8) : null
    }, null, 2));
    console.log('Cookies:', req.cookies);
    next();
});

// Ruta GET /api/users con diagnóstico completo
router.get('/', 
    (req, res, next) => {
        console.log('\n[Middleware 1] - Antes de verifyToken');
        next();
    },
    verifyToken,
    (req, res, next) => {
        console.log('\n[Middleware 2] - Después de verifyToken', {
            userId: req.userId,
            userRole: req.userRole
        });
        next();
    },
    checkRole('admin', 'coordinator', 'auxiliary'),
    (req, res, next) => {
        console.log('\n[Middleware 3] - Después de checkRole');
        next();
    },
    userController.getAllUsers
);

// Mantener todas las demás rutas exactamente igual
router.post('/', verifyToken, checkRole('admin'), userController.createUser);
router.put('/:id', verifyToken, checkRole('admin', 'coordinator'), userController.updateUser);
router.delete('/:id', verifyToken, checkRole('admin'), userController.deleteUser);
router.get('/:id', 
    verifyToken,
    checkRole('admin', 'coordinator'),
    userController.getUserById
);

module.exports = router;