const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authJwt, verifySignUp, role } = require('../middlewares');

// GET /api/users - Solo Admin
router.get(
  '/',
  [authJwt.verifyToken, role.checkRole(['admin'])],
  userController.getAllUsers
);

// GET /api/users/:id - Admin ve todo, coordinador/auxiliar solo su perfil
router.get(
  '/:id',
  authJwt.verifyToken,
  userController.getUserById
);

// POST /api/users - Admin y Coordinador
router.post(
  '/',
  [
    authJwt.verifyToken,
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
    authJwt.verifyToken,
    role.checkRole(['admin', 'coordinador']),
    verifySignUp.checkRolesExisted
  ],
  userController.updateUser
);

// DELETE /api/users/:id - Solo Admin
router.delete(
  '/:id',
  [authJwt.verifyToken, role.checkRole(['admin'])],
  userController.deleteUser
);

module.exports = router;