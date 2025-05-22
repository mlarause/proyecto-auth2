const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authJwt, role } = require('../middlewares');

// Todas las rutas requieren autenticación
router.use(authJwt.verifyToken);

router.get('/', role.checkRole(['admin']), userController.getAllUsers);
router.get('/:id', userController.getUserById);
router.post('/', role.checkRole(['admin', 'coordinador']), userController.createUser);
router.put('/:id', role.checkRole(['admin', 'coordinador']), userController.updateUser);
router.delete('/:id', role.checkRole(['admin']), userController.deleteUser);

module.exports = router;