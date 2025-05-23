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
        // Crear usuario
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8)
        });

        // Guardar usuario en la base de datos
        const savedUser = await user.save();

        // Generar token JWT
        const token = jwt.sign({ id: savedUser._id }, config.secret, {
            expiresIn: 86400 // 24 horas
        });

        // Responder con éxito
        res.status(200).json({
            success: true,
            message: "Usuario registrado correctamente",
            token: token,
            user: {
                id: savedUser._id,
                username: savedUser.username,
                email: savedUser.email
            }
        });

    } catch (error) {
        console.error("Error en registro:", error);
        res.status(500).json({
            success: false,
            message: "Error al registrar usuario",
            error: error.message
        });
    }
};
// 2. Login (común para todos)
exports.signin = async (req, res) => {
    try {
        // 1. Buscar usuario
        const user = await User.findOne({ username: req.body.username });
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Usuario no encontrado"
            });
        }

        // 2. Verificar contraseña
        const passwordIsValid = bcrypt.compareSync(
            req.body.password,
            user.password
        );

        if (!passwordIsValid) {
            return res.status(401).json({
                success: false,
                message: "Contraseña incorrecta"
            });
        }

        // 3. Generar token
        const token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: config.jwtExpiration
        });

        // 4. Responder con los datos
        res.status(200).json({
            success: true,
            message: "Autenticación exitosa",
            token: token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                roles: user.roles
            }
        });

    } catch (error) {
        console.error("[AuthController] Error en signin:", error);
        res.status(500).json({
            success: false,
            message: "Error durante el login"
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
    console.log('\n=== INICIO CONSULTA POR ID - SOLUCIÓN DEFINITIVA ===');
    
    try {
        // 1. Validación extrema del ID
        const id = req.params.id;
        console.log('[1] ID recibido:', id);
        
        if (!id || typeof id !== 'string' || id.length !== 24) {
            console.log('[ERROR] ID inválido');
            return res.status(400).json({ 
                success: false,
                message: "ID de usuario no válido" 
            });
        }

        // 2. Control de acceso (como en otros endpoints)
        console.log('[2] Verificando permisos...');
        const isAllowed = req.roles.includes('admin') || 
                        req.roles.includes('coordinator') || 
                        req.userId === id;
        
        if (!isAllowed) {
            console.log('[PERMISO DENEGADO]');
            return res.status(403).json({
                success: false,
                message: "No autorizado"
            });
        }

        // 3. Consulta directa a MongoDB (sin relaciones)
        console.log('[3] Ejecutando consulta directa...');
        const db = req.app.get('mongoDb'); // Conexión directa a MongoDB
        
        // 3.1 Buscar usuario
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(id) },
            { projection: { _id: 1, username: 1, email: 1, createdAt: 1, updatedAt: 1 } }
        );
        
        console.log('[4] Usuario encontrado:', user);
        if (!user) {
            console.log('[ERROR] Usuario no existe');
            return res.status(404).json({
                success: false,
                message: "Usuario no encontrado"
            });
        }

        // 3.2 Buscar roles en dos pasos explícitos
        console.log('[5] Buscando roles...');
        const userRoles = await db.collection('user_roles').find(
            { userId: new ObjectId(id) }
        ).toArray();
        
        const roleIds = userRoles.map(ur => ur.roleId);
        const roles = await db.collection('roles').find(
            { _id: { $in: roleIds } }
        ).toArray();

        console.log('[6] Roles encontrados:', roles.map(r => r.name));

        // 4. Formatear respuesta (igual que otros endpoints)
        const response = {
            success: true,
            data: {
                id: user._id,
                username: user.username,
                email: user.email,
                roles: roles.map(r => r.name),
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            }
        };

        console.log('[7] CONSULTA EXITOSA');
        return res.json(response);

    } catch (error) {
        console.error('[ERROR CRÍTICO]', {
            message: error.message,
            stack: error.stack,
            timestamp: new Date().toISOString(),
            details: {
                errorCode: error.code || 'N/A',
                errorType: error.name
            }
        });
        
        return res.status(500).json({
            success: false,
            message: "Error al obtener usuario",
            error: process.env.NODE_ENV === 'development' ? {
                type: error.name,
                message: error.message,
                code: error.code
            } : undefined
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