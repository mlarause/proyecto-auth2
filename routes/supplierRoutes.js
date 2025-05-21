const express = require('express');
const router = express.Router();
const supplierController = require('../controllers/supplierController');
const { authenticate, authorize } = require('../middlewares/auth');

// Aplicar autenticación a todas las rutas
router.use(authenticate);

// Endpoints específicos (SOLO para proveedores)
router.post('/', 
  (req, res, next) => {
    if (['admin', 'coordinador'].includes(req.user.role)) {
      return next();
    }
    return res.status(403).json({
      success: false,
      message: 'Acceso denegado: Se requiere rol admin o coordinador'
    });
  }, 
  supplierController.createSupplier
);

// Mantener todas las demás rutas EXACTAMENTE como están en tu repositorio
router.get('/', supplierController.getSuppliers);
router.get('/:id', supplierController.getSupplierById);
router.put('/:id', supplierController.updateSupplier);
router.delete('/:id', supplierController.deleteSupplier);

module.exports = router;