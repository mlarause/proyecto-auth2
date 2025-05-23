const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/auth.config');

// Roles del sistema
const ROLES = {
  ADMIN: 'admin',
  COORDINADOR: 'coordinador',
  AUXILIAR: 'auxiliar'
};

// Función para verificar permisos
const checkPermission = (userRole, allowedRoles) => {
  return allowedRoles.includes(userRole);
};

// 1. Registro de usuarios (SOLO ADMIN)
exports.signup = async (req, res) => {
  try {
    // 1. Verificar si ya existe algún usuario (para evitar registros múltiples)
    const userCount = await User.countDocuments();
    
    if (userCount > 0) {
      return res.status(403).json({
        success: false,
        message: 'El registro está cerrado. Contacta al administrador.'
      });
    }

    // 2. Validar campos requeridos
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Nombre, email y contraseña son requeridos'
      });
    }

    // 3. Crear primer usuario (admin por defecto)
    const newUser = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: bcrypt.hashSync(password, 8),
      role: 'admin' // Rol de administrador por defecto
    });

    await newUser.save();

    // 4. Respuesta exitosa
    return res.status(201).json({
      success: true,
      message: 'Administrador inicial creado exitosamente',
      data: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (error) {
    console.error('Error en signup:', error);
    
    // Manejo de errores de duplicados
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'El email ya está registrado'
      });
    }
    
    return res.status(500).json({
      success: false,
      message: 'Error al registrar usuario'
    });
  }
};

// 2. Login (común para todos)
exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email y contraseña son requeridos'
      });
    }

    const user = await User.findOne({ email: email.trim() }).select('+password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      config.secret,
      { expiresIn: '24h' }
    );

    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Error en signin:', error);
    return res.status(500).json({
      success: false,
      message: 'Error en el servidor'
    });
  }
};

// 3. Obtener todos los usuarios (Admin y Coordinador)
exports.getAllUsers = async (req, res) => {
  try {
    // Verificar permisos
    if (!checkPermission(req.userRole, [ROLES.ADMIN, ROLES.COORDINADOR])) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para ver usuarios'
      });
    }

    const users = await User.find({}).select('-password -__v');
    return res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });

  } catch (error) {
    console.error('Error en getAllUsers:', error);
    return res.status(500).json({
      success: false,
      message: 'Error al consultar usuarios'
    });
  }
};

// 4. Obtener usuario por ID (Admin y Coordinador)
exports.getUserById = async (req, res) => {
  try {
    // Verificar permisos
    if (!checkPermission(req.userRole, [ROLES.ADMIN, ROLES.COORDINADOR])) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para ver usuarios'
      });
    }

    const user = await User.findById(req.params.id).select('-password -__v');
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "Usuario no encontrado" 
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });

  } catch (error) {
    console.error('Error en getUserById:', error);
    res.status(500).json({ 
      success: false,
      message: "Error al obtener usuario"
    });
  }
};

// 5. Actualizar usuario (Admin puede actualizar todos, Coordinador solo auxiliares, Auxiliar solo sí mismo)
exports.updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const currentUserRole = req.userRole;
    const currentUserId = req.userId;

    // Buscar usuario a actualizar
    const userToUpdate = await User.findById(id);
    if (!userToUpdate) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // Verificar permisos
    if (currentUserRole === ROLES.AUXILIAR && userToUpdate._id.toString() !== currentUserId) {
      return res.status(403).json({
        success: false,
        message: 'Solo puedes modificar tu propio perfil'
      });
    }

    if (currentUserRole === ROLES.COORDINADOR && userToUpdate.role === ROLES.ADMIN) {
      return res.status(403).json({
        success: false,
        message: 'No puedes modificar administradores'
      });
    }

    // Actualizar campos permitidos
    const allowedFields = ['name', 'email'];
    if (currentUserRole === ROLES.ADMIN) {
      allowedFields.push('role');
    }

    const filteredUpdates = {};
    Object.keys(updates).forEach(key => {
      if (allowedFields.includes(key)) {
        filteredUpdates[key] = updates[key];
      }
    });

    // Si se actualiza password, hacer hash
    if (updates.password) {
      filteredUpdates.password = bcrypt.hashSync(updates.password, 8);
    }

    const updatedUser = await User.findByIdAndUpdate(id, filteredUpdates, { new: true }).select('-password -__v');

    return res.status(200).json({
      success: true,
      message: 'Usuario actualizado',
      data: updatedUser
    });

  } catch (error) {
    console.error('Error en updateUser:', error);
    return res.status(500).json({
      success: false,
      message: 'Error al actualizar usuario'
    });
  }
};

// 6. Eliminar usuario (SOLO ADMIN)
exports.deleteUser = async (req, res) => {
  try {
    // Verificar que sea admin
    if (!checkPermission(req.userRole, [ROLES.ADMIN])) {
      return res.status(403).json({
        success: false,
        message: 'Solo administradores pueden eliminar usuarios'
      });
    }

    const deletedUser = await User.findByIdAndDelete(req.params.id);
    
    if (!deletedUser) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Usuario eliminado correctamente'
    });

  } catch (error) {
    console.error('Error en deleteUser:', error);
    return res.status(500).json({
      success: false,
      message: 'Error al eliminar usuario'
    });
  }
};