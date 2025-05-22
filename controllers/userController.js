const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');

// [1] Obtener todos los usuarios (Solo Admin)
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .populate('supplier', 'name contact'); // Relación con proveedor si existe
    
    res.status(200).json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuarios',
      error: error.message
    });
  }
};

// [2] Obtener usuario por ID (con control de acceso)
exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password')
      .populate('supplier', 'name contact'); // Relación con proveedor

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // Validación para auxiliares (solo pueden verse a sí mismos)
    if (req.userRole === 'auxiliar' && req.userId !== user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'No autorizado para ver este usuario'
      });
    }

    // Validación para coordinadores (no pueden ver admin)
    if (req.userRole === 'coordinador' && user.role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para ver este usuario'
      });
    }

    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener usuario',
      error: error.message
    });
  }
};

// [3] Crear usuario (Admin y Coordinador)
exports.createUser = async (req, res) => {
  try {
    const { username, email, password, role, supplier } = req.body;

    // Validación básica
    if (!username || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: 'Todos los campos son requeridos'
      });
    }

    const newUser = new User({
      username,
      email,
      password: await bcrypt.hash(password, 10),
      role,
      supplier // Relación con proveedor si aplica
    });

    const savedUser = await newUser.save();

    // Generar token JWT (opcional para creación)
    const token = jwt.sign(
      { id: savedUser._id, role: savedUser.role },
      config.SECRET,
      { expiresIn: config.TOKEN_EXPIRATION }
    );

    res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      user: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email,
        role: savedUser.role,
        supplier: savedUser.supplier
      },
      token
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al crear usuario',
      error: error.message
    });
  }
};

// [4] Actualizar usuario (Admin y Coordinador)
exports.updateUser = async (req, res) => {
  try {
    const { username, email, role, supplier } = req.body;

    // Preparar datos a actualizar
    const updateData = { username, email, role, supplier };
    
    // No permitir que coordinadores actualicen a admin
    if (req.userRole === 'coordinador' && role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'No puedes asignar rol de administrador'
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Usuario actualizado correctamente',
      user: updatedUser
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al actualizar usuario',
      error: error.message
    });
  }
};

// [5] Eliminar usuario (Solo Admin)
exports.deleteUser = async (req, res) => {
  try {
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

// [6] Cambiar contraseña (para el propio usuario)
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.userId);

    // Verificar contraseña actual
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Contraseña actual incorrecta'
      });
    }

    // Actualizar contraseña
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Contraseña actualizada correctamente'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al cambiar contraseña',
      error: error.message
    });
  }
};

// [7] Obtener perfil del usuario logueado
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password')
      .populate('supplier', 'name contact');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error al obtener perfil',
      error: error.message
    });
  }
};

// [8] Buscar usuarios por criterios (Admin)
exports.searchUsers = async (req, res) => {
  try {
    const { role, username, email } = req.query;
    const query = {};

    if (role) query.role = role;
    if (username) query.username = { $regex: username, $options: 'i' };
    if (email) query.email = { $regex: email, $options: 'i' };

    const users = await User.find(query)
      .select('-password')
      .populate('supplier', 'name contact');

    res.status(200).json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error en búsqueda de usuarios',
      error: error.message
    });
  }
};