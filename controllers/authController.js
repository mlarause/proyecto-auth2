const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/auth.config');

exports.signin = async (req, res) => {
    try {
        // Validación básica
        if (!req.body.email || !req.body.password) {
            return res.status(400).json({
                success: false,
                message: 'Email y contraseña son requeridos'
            });
        }

        // Buscar usuario (similar a otros módulos)
        const user = await User.findOne({ 
            email: req.body.email,
            status: true 
        });

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Credenciales inválidas'
            });
        }

        // Validar contraseña
        const validPassword = bcrypt.compareSync(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: 'Credenciales inválidas'
            });
        }

        // Generar token (similar a otros módulos)
        const token = jwt.sign(
            {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            config.secret,
            { expiresIn: '24h' }
        );

        // Respuesta exitosa
        res.status(200).json({
            success: true,
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            accessToken: token
        });

    } catch (error) {
        console.error('Error en authController.signin:', error);
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
};

exports.signup = async (req, res) => {
    try {
        // Validación básica
        if (!req.body.name || !req.body.email || !req.body.password) {
            return res.status(400).json({
                success: false,
                message: 'Nombre, email y contraseña son requeridos'
            });
        }

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'El email ya está registrado'
            });
        }

        // Crear nuevo usuario
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8),
            role: req.body.role || 'auxiliar'
        });

        await user.save();

        res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente'
        });

    } catch (error) {
        console.error('Error en authController.signup:', error);
        res.status(500).json({
            success: false,
            message: 'Error al registrar usuario'
        });
    }
};