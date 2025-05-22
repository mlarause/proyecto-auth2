const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authJwt, verifySignUp, role } = require('../middlewares');

// Aplicar autenticación a todas las rutas de usuarios
router.use(authJwt.verifyToken);

// GET /api/users - Solo Admin
router.get(
  '/',
  role.checkRole(['admin']),
  userController.getAllUsers
);

// GET /api/users/:id - Acceso controlado en controller
router.get(
  '/:id',
  userController.getUserById
);

// POST /api/users - Admin y Coordinador
router.post(
  '/',
  [
    role.checkRole(['admin', 'coordinador']),
    verifySignUp.checkDuplicateUsernameOrEmail,
    verifySignUp.checkRolesExisted
  ],
  userController.createUser
);

// PUT /api/users/:id - Admin y Coordinador
router.put(
  '/:id',
  [
    role.checkRole(['admin', 'coordinador']),
    verifySignUp.checkRolesExisted
  ],
  userController.updateUser
);

// DELETE /api/users/:id - Solo Admin
router.delete(
  '/:id',
  role.checkRole(['admin']),
  userController.deleteUser
);

module.exports = router;