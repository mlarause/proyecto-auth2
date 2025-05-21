const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authJwt = require('../middlewares/authJwt');

// Rutas para usuarios
router.get('/all', [authJwt.verifyToken, authJwt.isAdmin], userController.getAllUsers);
router.get('/:id', [authJwt.verifyToken], userController.getUserById);
router.put('/:id', [authJwt.verifyToken, authJwt.isAdmin], userController.updateUser);
router.delete('/:id', [authJwt.verifyToken, authJwt.isAdmin], userController.deleteUser);

module.exports = router;