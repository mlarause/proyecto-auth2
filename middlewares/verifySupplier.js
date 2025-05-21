const db = require("../models");
const Supplier = db.supplier;

checkDuplicateSupplier = async (req, res, next) => {
  try {
    // Verificar por email duplicado
    const supplierByEmail = await Supplier.findOne({ 
      email: req.body.email 
    });
    
    if (supplierByEmail) {
      return res.status(400).json({
        success: false,
        message: "El email ya está registrado"
      });
    }

    // Verificar por nombre duplicado
    const supplierByName = await Supplier.findOne({ 
      name: req.body.name 
    });
    
    if (supplierByName) {
      return res.status(400).json({
        success: false,
        message: "El nombre de proveedor ya existe"
      });
    }

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error al verificar proveedor",
      error: error.message
    });
  }
};

module.exports = {
  checkDuplicateSupplier
};