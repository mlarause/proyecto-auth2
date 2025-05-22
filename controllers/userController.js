const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');

// [1] Obtener todos los usuarios (SOLO ADMIN)
exports.getAllUsers = async (req, res) => {
  try {
    // Verificar rol de admin (doble validación)
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Requiere rol de administrador'
      });
    }

    const users = await User.find().select('-password -__v');
    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuarios',
      error: error.message
    });
  }
};

// [2] Obtener usuario por ID (con control de roles)
exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -__v');
    
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
        message: 'No tienes permisos para ver este usuario'
      });
    }

    // Coordinador no puede ver admin
    if (req.user.role === 'coordinador' && user.role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'No autorizado para ver este usuario'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuario',
      error: error.message
    });
  }
};

// [3] Crear usuario (ADMIN y COORDINADOR)
exports.createUser = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Validar campos
    if (!username || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: 'Todos los campos son requeridos'
      });
    }

    // Coordinador no puede crear admin
    if (req.user.role === 'coordinador' && role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'No puedes crear usuarios con rol de administrador'
      });
    }

    const newUser = new User({
      username,
      email,
      password: await bcrypt.hash(password, 10),
      role
    });

    const savedUser = await newUser.save();

    res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      data: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email,
        role: savedUser.role,
        createdAt: savedUser.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al crear usuario',
      error: error.message
    });
  }
};

// [4] Actualizar usuario (ADMIN y COORDINADOR)
exports.updateUser = async (req, res) => {
  try {
    const { username, email, role } = req.body;

    // Coordinador no puede actualizar a admin
    if (req.user.role === 'coordinador' && role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'No puedes asignar rol de administrador'
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { username, email, role },
      { new: true, runValidators: true }
    ).select('-password -__v');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Usuario actualizado correctamente',
      data: updatedUser
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al actualizar usuario',
      error: error.message
    });
  }
};

// [5] Eliminar usuario (SOLO ADMIN)
exports.deleteUser = async (req, res) => {
  try {
    // Validar que sea admin (doble validación)
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Requiere rol de administrador'
      });
    }

    // Prevenir auto-eliminación
    if (req.user.id === req.params.id) {
      return res.status(400).json({
        success: false,
        message: 'No puedes eliminarte a ti mismo'
      });
    }

    const deletedUser = await User.findByIdAndDelete(req.params.id);
    
    if (!deletedUser) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Usuario eliminado correctamente',
      deletedUserId: deletedUser._id
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al eliminar usuario',
      error: error.message
    });
  }
};

// [6] Obtener perfil del usuario logueado
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -__v');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener perfil',
      error: error.message
    });
  }
};