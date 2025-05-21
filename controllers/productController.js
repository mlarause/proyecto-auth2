const Product = require('../models/Product');
const Category = require('../models/Category');
const Subcategory = require('../models/Subcategory');

// @desc    Crear un nuevo producto
// @route   POST /api/products
// @access  Privado/Admin
exports.createProduct = async (req, res) => {
  try {
    const { name, description, price, stock, category, subcategory } = req.body;

    // Validación básica de campos requeridos
    if (!name || !description || !price || !stock || !category || !subcategory) {
      return res.status(400).json({
        success: false,
        message: 'Todos los campos son obligatorios'
      });
    }

    // Verificar que la categoría exista
    const categoryExists = await Category.findById(category);
    if (!categoryExists) {
      return res.status(404).json({
        success: false,
        message: 'La categoría especificada no existe'
      });
    }

    // Verificar que la subcategoría exista y pertenezca a la categoría
    const subcategoryExists = await Subcategory.findOne({
      _id: subcategory,
      category: category
    });

    if (!subcategoryExists) {
      return res.status(400).json({
        success: false,
        message: 'La subcategoría no existe o no pertenece a la categoría especificada'
      });
    }

    // Crear el producto sin el createdBy temporalmente
    const product = new Product({
      name,
      description,
      price,
      stock,
      category,
      subcategory
      // createdBy se agregará después de verificar el usuario
    });

    // Verificar si el usuario está disponible en el request
    if (req.user && req.user.id) {
      product.createdBy = req.user.id;
    }

    // Guardar en la base de datos
    const savedProduct = await product.save();

    // Obtener el producto con los datos poblados
    const productWithDetails = await Product.findById(savedProduct._id)
      .populate('category', 'name')
      .populate('subcategory', 'name');

    res.status(201).json({
      success: true,
      message: 'Producto creado exitosamente',
      data: productWithDetails
    });

  } catch (error) {
    console.error('Error en createProduct:', error);
    
    // Manejo de errores de MongoDB
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Ya existe un producto con ese nombre'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error al crear el producto',
      error: error.message
    });
  }
};

// @desc    Obtener todos los productos
// @route   GET /api/products
// @access  Público
exports.getProducts = async (req, res) => {
  try {
    const products = await Product.find()
      .populate('category', 'name')
      .populate('subcategory', 'name')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: products.length,
      data: products
    });
  } catch (error) {
    console.error('Error en getProducts:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener los productos'
    });
  }
};

// @desc    Obtener un producto por ID
// @route   GET /api/products/:id
// @access  Público
exports.getProductById = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate('category', 'name description')
      .populate('subcategory', 'name description');

    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Producto no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      data: product
    });
  } catch (error) {
    console.error('Error en getProductById:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener el producto'
    });
  }
};

// @desc    Actualizar un producto
// @route   PUT /api/products/:id
// @access  Privado/Admin
exports.updateProduct = async (req, res) => {
  try {
    const { name, description, price, stock, category, subcategory } = req.body;
    const updateData = {};

    // Validar y preparar datos para actualización
    if (name) updateData.name = name;
    if (description) updateData.description = description;
    if (price) updateData.price = price;
    if (stock) updateData.stock = stock;

    // Validar relaciones si se actualizan
    if (category || subcategory) {
      if (category) {
        const categoryExists = await Category.findById(category);
        if (!categoryExists) {
          return res.status(404).json({
            success: false,
            message: 'La categoría especificada no existe'
          });
        }
        updateData.category = category;
      }

      if (subcategory) {
        const subcategoryExists = await Subcategory.findOne({
          _id: subcategory,
          category: category || updateData.category
        });

        if (!subcategoryExists) {
          return res.status(400).json({
            success: false,
            message: 'La subcategoría no existe o no pertenece a la categoría'
          });
        }
        updateData.subcategory = subcategory;
      }
    }

    // Actualizar el producto
    const updatedProduct = await Product.findByIdAndUpdate(
      req.params.id,
      updateData,
      { 
        new: true,
        runValidators: true
      }
    )
    .populate('category', 'name')
    .populate('subcategory', 'name');

    if (!updatedProduct) {
      return res.status(404).json({
        success: false,
        message: 'Producto no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Producto actualizado exitosamente',
      data: updatedProduct
    });

  } catch (error) {
    console.error('Error en updateProduct:', error);
    res.status(500).json({
      success: false,
      message: 'Error al actualizar el producto'
    });
  }
};

// @desc    Eliminar un producto
// @route   DELETE /api/products/:id
// @access  Privado/Admin
exports.deleteProduct = async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);

    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Producto no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Producto eliminado exitosamente',
      data: product
    });

  } catch (error) {
    console.error('Error en deleteProduct:', error);
    res.status(500).json({
      success: false,
      message: 'Error al eliminar el producto'
    });
  }
};