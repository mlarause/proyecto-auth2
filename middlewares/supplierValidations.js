const { body } = require('express-validator');
const Supplier = require('../models/Supplier');
const Product = require('../models/Product');

exports.validateSupplierData = [
  body('name')
    .notEmpty().withMessage('El nombre es requerido')
    .isLength({ max: 100 }).withMessage('Máximo 100 caracteres'),
  
  body('email')
    .notEmpty().withMessage('El email es requerido')
    .isEmail().withMessage('Email inválido')
    .custom(async (value, { req }) => {
      const supplier = await Supplier.findOne({ email: value });
      if (supplier && supplier._id.toString() !== req.params?.id) {
        throw new Error('El email ya está registrado');
      }
      return true;
    }),
  
  body('products')
    .optional()
    .isArray().withMessage('Debe ser un arreglo de IDs')
    .custom(async (products) => {
      if (products && products.length > 0) {
        const count = await Product.countDocuments({ _id: { $in: products } });
        if (count !== products.length) {
          throw new Error('Algunos productos no existen');
        }
      }
      return true;
    }),
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];