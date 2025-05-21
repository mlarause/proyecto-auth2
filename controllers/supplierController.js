const Supplier = require('../models/Supplier');
const Product = require('../models/Product');

/**
 * @desc    Crear un nuevo proveedor
 * @route   POST /api/suppliers
 * @access  Privado (Admin/Coordinador)
 */
exports.createSupplier = async (req, res) => {
  try {
    const { name, contact, email, phone, address, products } = req.body;

    // Validación manual de productos
    const validProducts = await Product.find({ _id: { $in: products } });
    if (validProducts.length !== products.length) {
      return res.status(400).json({
        success: false,
        message: 'Algunos productos no existen'
      });
    }

    // Crear proveedor
    const supplier = new Supplier({
      name,
      contact,
      email,
      phone,
      address,
      products,
      createdBy: req.user._id
    });

    await supplier.save();

    // Respuesta exitosa
    res.status(201).json({
      success: true,
      data: {
        ...supplier.toObject(),
        products: validProducts.map(p => ({ _id: p._id, name: p.name }))
      }
    });

  } catch (error) {
    console.error('Error en createSupplier:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'El proveedor ya existe (nombre o email duplicado)'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error al crear proveedor'
    });
  }
};

/**
 * @desc    Obtener todos los proveedores
 * @route   GET /api/suppliers
 * @access  Privado (Admin/Coordinador/Auxiliar)
 */
exports.getSuppliers = async (req, res) => {
  try {
    const suppliers = await Supplier.find()
      .populate('products', 'name')
      .populate('createdBy', 'name');

    res.status(200).json({
      success: true,
      count: suppliers.length,
      data: suppliers
    });

  } catch (error) {
    console.error('Error en getSuppliers:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener proveedores'
    });
  }
};

/**
 * @desc    Obtener proveedor por ID
 * @route   GET /api/suppliers/:id
 * @access  Privado (Admin/Coordinador/Auxiliar)
 */
exports.getSupplierById = async (req, res) => {
  try {
    const supplier = await Supplier.findById(req.params.id)
      .populate('products', 'name price')
      .populate('createdBy', 'name email');

    if (!supplier) {
      return res.status(404).json({
        success: false,
        message: 'Proveedor no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      data: supplier
    });

  } catch (error) {
    console.error('Error en getSupplierById:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({
        success: false,
        message: 'ID de proveedor inválido'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error al obtener proveedor'
    });
  }
};

/**
 * @desc    Actualizar proveedor
 * @route   PUT /api/suppliers/:id
 * @access  Privado (Admin/Coordinador)
 */
exports.updateSupplier = async (req, res) => {
  try {
    const { products, ...updateData } = req.body;

    // Validar productos si se envían
    if (products) {
      const productsExist = await Product.countDocuments({ _id: { $in: products } });
      if (productsExist !== products.length) {
        return res.status(400).json({
          success: false,
          message: 'Uno o más productos no existen'
        });
      }
      updateData.products = products;
    }

    // Actualizar proveedor
    const updatedSupplier = await Supplier.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    )
    .populate('products', 'name')
    .populate('createdBy', 'name email');

    if (!updatedSupplier) {
      return res.status(404).json({
        success: false,
        message: 'Proveedor no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      data: updatedSupplier
    });

  } catch (error) {
    console.error('Error en updateSupplier:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'El nombre o email ya está en uso'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error al actualizar proveedor'
    });
  }
};

/**
 * @desc    Eliminar proveedor
 * @route   DELETE /api/suppliers/:id
 * @access  Privado (Admin)
 */
exports.deleteSupplier = async (req, res) => {
  try {
    const supplier = await Supplier.findByIdAndDelete(req.params.id);

    if (!supplier) {
      return res.status(404).json({
        success: false,
        message: 'Proveedor no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      data: supplier
    });

  } catch (error) {
    console.error('Error en deleteSupplier:', error);
    res.status(500).json({
      success: false,
      message: 'Error al eliminar proveedor'
    });
  }
};

/**
 * @desc    Obtener proveedores por producto
 * @route   GET /api/suppliers/product/:productId
 * @access  Privado (Admin/Coordinador/Auxiliar)
 */
exports.getSuppliersByProduct = async (req, res) => {
  try {
    const suppliers = await Supplier.find({ products: req.params.productId })
      .populate('products', 'name')
      .populate('createdBy', 'name');

    res.status(200).json({
      success: true,
      count: suppliers.length,
      data: suppliers
    });

  } catch (error) {
    console.error('Error en getSuppliersByProduct:', error);
    res.status(500).json({
      success: false,
      message: 'Error al obtener proveedores por producto'
    });
  }
};