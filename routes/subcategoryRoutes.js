const express = require('express');
const router = express.Router();
const subcategoryController = require('../controllers/subcategoryController');
const { check } = require('express-validator');

// Validaciones
const validateSubcategory = [
  check('name').not().isEmpty().withMessage('El nombre es obligatorio'),
  check('description').not().isEmpty().withMessage('La descripción es obligatoria'),
  check('category').not().isEmpty().withMessage('La categoría padre es requerida')
];

// Rutas
router.post('/', validateSubcategory, subcategoryController.createSubcategory);
router.get('/', subcategoryController.getSubcategories);
router.get('/:id', subcategoryController.getSubcategoryById);
router.put('/:id', validateSubcategory, subcategoryController.updateSubcategory);
router.delete('/:id', subcategoryController.deleteSubcategory);

module.exports = router;