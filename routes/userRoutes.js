const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authJwt, verifySignUp, role } = require('../middlewares');

// Middleware de autenticación para todas las rutas
router.use((req, res, next) => {
  console.log(`[ROUTE] Acceso a ruta: ${req.method} ${req.path}`); // Diagnóstico
  authJwt.verifyToken(req, res, next);
});

// GET /api/users - Solo Admin
router.get('/', 
  (req, res, next) => {
    console.log('[ROLE] Verificando roles para GET /users', req.user); // Diagnóstico
    role.checkRole(['admin'])(req, res, next);
  }, 
  userController.getAllUsers
);

// GET /api/users/:id - Acceso controlado
router.get('/:id', userController.getUserById);

// POST /api/users - Admin y Coordinador
router.post('/',
  [
    (req, res, next) => {
      console.log('[ROLE] Verificando roles para POST /users', req.user); // Diagnóstico
      role.checkRole(['admin', 'coordinador'])(req, res, next);
    },
    verifySignUp.checkDuplicateUsernameOrEmail,
    verifySignUp.checkRolesExisted
  ],
  userController.createUser
);

// PUT /api/users/:id - Admin y Coordinador
router.put('/:id',
  [
    role.checkRole(['admin', 'coordinador']),
    verifySignUp.checkRolesExisted
  ],
  userController.updateUser
);

// DELETE /api/users/:id - Solo Admin
router.delete('/:id',
  (req, res, next) => {
    console.log('[ROLE] Verificando roles para DELETE /users', req.user); // Diagnóstico
    role.checkRole(['admin'])(req, res, next);
  },
  userController.deleteUser
);

module.exports = router;