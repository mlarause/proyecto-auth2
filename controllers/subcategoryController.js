const Subcategory = require('../models/Subcategory');
const Category = require('../models/Category');

// Crear subcategoría
exports.createSubcategory = async (req, res) => {
  try {
    const { name, description, category } = req.body;

    // Validar que la categoría padre exista
    const parentCategory = await Category.findById(category);
    if (!parentCategory) {
      return res.status(404).json({
        success: false,
        message: 'La categoría padre no existe'
      });
    }

    const newSubcategory = new Subcategory({
      name: name.trim(),
      description: description.trim(),
      category
    });

    await newSubcategory.save();

    res.status(201).json({
      success: true,
      message: 'Subcategoría creada exitosamente',
      data: newSubcategory
    });

  } catch (error) {
    console.error('Error al crear subcategoría:', error);
    
    if (error.message.includes('duplicate key') || error.message.includes('Ya existe')) {
      return res.status(400).json({
        success: false,
        message: 'Ya existe una subcategoría con ese nombre'
      });
    }

    res.status(500).json({
      success: false,
      message: error.message || 'Error al crear subcategoría'
    });
  }
};

// Obtener todas las subcategorías
exports.getSubcategories = async (req, res) => {
  try {
    const subcategories = await Subcategory.find().populate('category', 'name');
    res.status(200).json({
      success: true,
      data: subcategories
    });
  } catch (error) {
    console.error('Error al obtener subcategorías:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener subcategorías'
    });
  }
};

// Obtener subcategoría por ID
exports.getSubcategoryById = async (req, res) => {
  try {
    const subcategory = await Subcategory.findById(req.params.id).populate('category', 'name');
    if (!subcategory) {
      return res.status(404).json({
        success: false,
        message: 'Subcategoría no encontrada'
      });
    }
    res.status(200).json({
      success: true,
      data: subcategory
    });
  } catch (error) {
    console.error('Error al obtener subcategoría:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener subcategoría'
    });
  }
};

// Actualizar subcategoría
exports.updateSubcategory = async (req, res) => {
  try {
    const { name, description, category } = req.body;

    // Verificar si se cambia la categoría padre
    if (category) {
      const parentCategory = await Category.findById(category);
      if (!parentCategory) {
        return res.status(404).json({
          success: false,
          message: 'La categoría padre no existe'
        });
      }
    }

    const updatedSubcategory = await Subcategory.findByIdAndUpdate(
      req.params.id,
      {
        name: name ? name.trim() : undefined,
        description: description ? description.trim() : undefined,
        category
      },
      { new: true, runValidators: true }
    );

    if (!updatedSubcategory) {
      return res.status(404).json({
        success: false,
        message: 'Subcategoría no encontrada'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Subcategoría actualizada',
      data: updatedSubcategory
    });
  } catch (error) {
    console.error('Error al actualizar subcategoría:', error);
    res.status(500).json({
      success: false,
      message: 'Error al actualizar subcategoría'
    });
  }
};

// Eliminar subcategoría
exports.deleteSubcategory = async (req, res) => {
  try {
    const deletedSubcategory = await Subcategory.findByIdAndDelete(req.params.id);
    if (!deletedSubcategory) {
      return res.status(404).json({
        success: false,
        message: 'Subcategoría no encontrada'
      });
    }
    res.status(200).json({
      success: true,
      message: 'Subcategoría eliminada'
    });
  } catch (error) {
    console.error('Error al eliminar subcategoría:', error);
    res.status(500).json({
      success: false,
      message: 'Error al eliminar subcategoría'
    });
  }
};