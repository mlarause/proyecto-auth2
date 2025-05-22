const express = require('express');
const router = express.Router();
const controller = require('../controllers/userController');
const { authJwt, role } = require('../middlewares');

// Todas las rutas requieren autenticación
router.use(authJwt.verifyToken);

router.get('/', role.checkRole(['admin']), controller.getAll);
router.get('/:id', controller.getById);
router.post('/', role.checkRole(['admin', 'coordinador']), controller.create);
router.put('/:id', role.checkRole(['admin', 'coordinador']), controller.update);
router.delete('/:id', role.checkRole(['admin']), controller.delete);

module.exports = router;