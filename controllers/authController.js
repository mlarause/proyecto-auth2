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
            role: role || 'auxiliary'
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
    console.log('\n=== INICIO DE SESIÓN - DIAGNÓSTICO ===');
    
    try {
        // 1. Log completa del request recibido
        console.log('\n[1] Request recibido:', {
            headers: req.headers,
            body: {
                email: req.body.email,
                password: req.body.password ? '***' : 'NO PROVISTA'
            },
            method: req.method,
            url: req.originalUrl
        });

        // 2. Validación de campos
        if (!req.body.email || !req.body.password) {
            console.log('\n[2] Error: Campos faltantes', {
                email_provisto: !!req.body.email,
                password_provisto: !!req.body.password
            });
            return res.status(400).json({
                success: false,
                message: 'Email y contraseña son requeridos'
            });
        }

        // 3. Búsqueda del usuario con logging extendido
        console.log('\n[3] Buscando usuario en BD:', {
            email_buscado: req.body.email.trim()
        });
        
        const user = await User.findOne({ 
            email: req.body.email.trim() 
        }).select('+password +status');
        
        console.log('\n[4] Resultado búsqueda usuario:', user ? {
            id: user._id,
            email: user.email,
            status: user.status,
            password_hash: user.password ? '***' : 'NO HASH'
        } : 'USUARIO NO ENCONTRADO');

        if (!user || user.status !== true) {
            console.log('\n[5] Error: Usuario no válido', {
                usuario_encontrado: !!user,
                estado_usuario: user?.status
            });
            return res.status(401).json({
                success: false,
                message: 'Credenciales inválidas'
            });
        }

        // 4. Comparación de contraseñas con diagnóstico detallado
        console.log('\n[6] Comparando contraseñas...');
        console.log('Contraseña recibida (plain):', req.body.password);
        console.log('Hash almacenado en BD:', user.password);
        
        const isMatch = await bcrypt.compare(req.body.password, user.password);
        console.log('\n[7] Resultado comparación bcrypt:', isMatch);

        if (!isMatch) {
            // Diagnóstico adicional: Generar hash temporal para comparación
            const tempHash = await bcrypt.hash(req.body.password, 8);
            console.log('\n[8] Diagnóstico hash:', {
                hash_generado_ahora: tempHash,
                hash_almacenado: user.password,
                coinciden: tempHash === user.password
            });
            
            return res.status(401).json({
                success: false,
                message: 'Credenciales inválidas'
            });
        }

        // 5. Generación de token
        console.log('\n[9] Generando token JWT...');
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            config.secret,
            { expiresIn: '24h' }
        );

        console.log('\n[10] Autenticación exitosa:', {
            usuario: user.email,
            rol: user.role,
            token: token.substring(0, 20) + '...'
        });

        return res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.log('\n[ERROR] Detalles del fallo:', {
            mensaje: error.message,
            stack: error.stack,
            tipo: error.name
        });
        return res.status(500).json({
            success: false,
            message: 'Error en el servidor'
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