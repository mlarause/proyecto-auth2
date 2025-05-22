const User = require('../models/User');

// Obtener todos los usuarios (Admin)
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.status(200).json({ 
      success: true,
      data: users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuarios'
    });
  }
};

// Obtener usuario por ID (con control de acceso)
exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // Auxiliar solo puede verse a sí mismo
    if (req.user.role === 'auxiliar' && req.user.id !== user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'No autorizado'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuario'
    });
  }
};

// Eliminar usuario (Admin)
exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Usuario eliminado correctamente'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al eliminar usuario'
    });
  }
};

// Funciones existentes (mantenidas igual)
exports.createUser = async (req, res) => {
  // ... (tu implementación actual)
};

exports.updateUser = async (req, res) => {
  // ... (tu implementación actual)
};