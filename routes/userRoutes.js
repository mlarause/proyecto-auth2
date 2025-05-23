const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { verifyToken } = require('../middlewares/authJwt');
const { checkRole } = require('../middlewares/role');

// Middleware de rastreo para diagnóstico (se puede eliminar después)
router.use((req, res, next) => {
    console.log('\n=== PETICIÓN USUARIOS ===');
    console.log('Método:', req.method);
    console.log('Ruta:', req.originalUrl);
    console.log('Headers:', {
        authorization: req.headers.authorization ? '***' + req.headers.authorization.slice(-10) : 'NO PROVISTO',
        'x-access-token': req.headers['x-access-token'] ? '***' + req.headers['x-access-token'].slice(-10) : 'NO PROVISTO'
    });
    next();
});

// GET /api/users - Listar todos los usuarios
router.get('/', 
    verifyToken, 
    checkRole('admin', 'coordinator', 'auxiliary'),
    userController.getAllUsers
);

// POST /api/users - Crear nuevo usuario
router.post('/', 
    verifyToken,
    checkRole('admin'),
    userController.createUser
);

// PUT /api/users/:id - Actualizar usuario
router.put('/:id', 
    verifyToken,
    checkRole('admin', 'coordinator'),
    userController.updateUser
);

// DELETE /api/users/:id - Eliminar usuario
router.delete('/:id', 
    verifyToken,
    checkRole('admin'),
    userController.deleteUser
);

module.exports = router;