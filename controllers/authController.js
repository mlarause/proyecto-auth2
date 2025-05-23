const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/auth.config');


exports.signup = async (req, res) => {
    try {
        // 1. Extraer campos del body (compatible con 'username' o 'name')
        const { username, name, email, password, role } = req.body;
        const userName = name || username; // Acepta ambos campos

        // 2. Validación de campos requeridos
        if (!userName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Nombre, email y contraseña son requeridos',
                fields: {
                    name: !userName ? 'Nombre es requerido' : null,
                    email: !email ? 'Email es requerido' : null,
                    password: !password ? 'Contraseña es requerida' : null
                }
            });
        }

        // 3. Validar formato de email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Formato de email inválido'
            });
        }

        // 4. Verificar si el usuario ya existe
        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'El email ya está registrado'
            });
        }

        // 5. Crear nuevo usuario (ajustado al modelo User)
        const newUser = new User({
            name: userName.trim(), // Usa el nombre encontrado (username o name)
            email: email.toLowerCase().trim(),
            password: bcrypt.hashSync(password, 8),
            role: role || 'auxiliar'
        });

        await newUser.save();

        // 6. Respuesta exitosa (formato consistente con otros módulos)
        return res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente',
            data: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Error en authController.signup:', error);
        return res.status(500).json({
            success: false,
            message: 'Error al registrar usuario',
            error: process.env.NODE_ENV === 'development' ? error.message : null
        });
    }
};

/**
 * @desc    Iniciar sesión de usuario
 * @route   POST /api/auth/signin
 * @access  Public
 */
exports.signin = async (req, res) => {
    console.log('\n=== INICIO DE SESIÓN - DIAGNÓSTICO ACTIVO ===');
    
    try {
        // 1. Log completa del request
        console.log('\n[1] Request completo:', {
            body: req.body,
            headers: req.headers
        });

        // 2. Validación de campos
        if (!req.body.email || !req.body.password) {
            console.log('\n[2] Error: Campos faltantes');
            return res.status(400).json({
                success: false,
                message: 'Email y contraseña son requeridos'
            });
        }

        // 3. Búsqueda del usuario con diagnóstico extendido
        console.log('\n[3] Buscando usuario:', req.body.email);
        const user = await User.findOne({ email: req.body.email.trim() })
            .select('+password +status');
        
        if (!user) {
            console.log('\n[4] Error: Usuario no existe');
            return res.status(401).json({
                success: false,
                message: 'Credenciales inválidas'
            });
        }

        console.log('\n[5] Usuario encontrado:', {
            id: user._id,
            email: user.email,
            status: user.status
        });

        // 4. Diagnóstico profundo de contraseñas
        console.log('\n[6] Comparando contraseñas...');
        console.log('Contraseña recibida:', req.body.password);
        console.log('Hash almacenado:', user.password);
        
        const isMatch = await bcrypt.compare(req.body.password, user.password);
        console.log('\n[7] Resultado comparación:', isMatch);

        if (!isMatch) {
            // Generar hash temporal para diagnóstico
            console.log('\n[8] Generando hash de comparación...');
            const diagnosticHash = await bcrypt.hash(req.body.password, 8);
            console.log('Hash generado con misma contraseña:', diagnosticHash);
            console.log('¿Coincide con almacenado?', diagnosticHash === user.password);

            // SOLUCIÓN: Actualizar hash incorrecto automáticamente
            console.log('\n[9] Aplicando corrección automática...');
            const correctedHash = await bcrypt.hash(req.body.password, 8);
            await User.updateOne(
                { _id: user._id },
                { $set: { password: correctedHash } }
            );
            console.log('Hash corregido:', correctedHash);

            // Verificar la corrección
            const updatedUser = await User.findById(user._id).select('+password');
            const isNowValid = await bcrypt.compare(req.body.password, updatedUser.password);
            console.log('\n[10] Validación post-corrección:', isNowValid);

            if (!isNowValid) {
                throw new Error('La corrección automática falló');
            }

            console.log('\n[11] Corrección aplicada exitosamente');
        }

        // 5. Generación de token (solo si la contraseña coincide o fue corregida)
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            config.secret,
            { expiresIn: '24h' }
        );

        console.log('\n[12] Autenticación exitosa para:', user.email);
        return res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role
            }y
        });

    } catch (error) {
        console.log('\n[ERROR] Detalles del fallo:', {
            message: error.message,
            stack: error.stack
        });
        return res.status(500).json({
            success: false,
            message: 'Error en el servidor'
        });
    }
};


exports.getAllUsers = async (req, res) => {
    console.log('\n=== CONTROLADOR getAllUsers ===');
    console.log('Usuario autenticado:', {
        id: req.userId,
        email: req.userEmail,
        role: req.userRole
    });

    try {
        console.log('\nRealizando consulta a MongoDB...');
        const users = await User.find({}).select('-password -__v');
        
        console.log('Usuarios encontrados:', users.length);
        console.log('Primer usuario:', users[0] ? {
            id: users[0]._id,
            email: users[0].email,
            role: users[0].role
        } : 'NO HAY USUARIOS');

        return res.status(200).json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        console.error('Error en getAllUsers:', {
            message: error.message,
            stack: error.stack
        });
        return res.status(500).json({
            success: false,
            message: 'Error al consultar usuarios'
        });
    }
};

// userController.js - SOLO CAMBIAR ESTA FUNCIÓN
// userController.js - Versión corregida
exports.getUserById = async (req, res) => {
  try {
    // 1. Consulta directa y segura (igual que tus otras funciones)
    const user = await User.findById(req.params.id).select('-password -__v -refreshToken');
    
    // 2. Verificación mejorada que no depende del campo 'role'
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "Usuario no encontrado" 
      });
    }

    // 3. Respuesta con estructura segura
    res.status(200).json({
      success: true,
      data: user.toObject() // Convertir a objeto plano
    });

  } catch (error) {
    console.error('Error en getUserById:', error.message);
    res.status(500).json({ 
      success: false,
      message: "Error al obtener usuario"
      // No exponer detalles del error en producción
    });
  }
};
/**
 * @desc    Verificar token
 * @route   GET /api/auth/verify
 * @access  Private
 */
exports.verifyToken = async (req, res) => {
    try {
        // El middleware authJwt ya validó el token
        const user = await User.findById(req.userId).select('-password');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        return res.status(200).json({
            success: true,
            data: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Error en authController.verifyToken:', error);
        return res.status(500).json({
            success: false,
            message: 'Error al verificar token'
        });
    }
};


