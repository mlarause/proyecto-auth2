const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');

exports.signup = async (req, res) => {
    try {
        const { username, email, password, rol } = req.body;

        // Validar si usuario existe
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({
                success: false,
                message: 'El usuario ya existe'
            });
        }

        // Encriptar contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Crear usuario
        const user = new User({
            username,
            email,
            password: hashedPassword,
            rol: rol || 'auxiliar'
        });

        await user.save();

        // Crear token (IMPORTANTE: usando "rol")
        const token = jwt.sign(
            { id: user._id, rol: user.rol },
            config.SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            success: true,
            message: 'Usuario registrado correctamente',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                rol: user.rol
            }
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error al registrar usuario',
            error: error.message
        });
    }
};

exports.signin = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validar usuario
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Validar contraseña
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({
                success: false,
                message: 'Credenciales inválidas'
            });
        }

        // Crear token (IMPORTANTE: usando "rol")
        const token = jwt.sign(
            { id: user._id, rol: user.rol },
            config.SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            success: true,
            message: 'Login exitoso',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                rol: user.rol
            }
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error al iniciar sesión',
            error: error.message
        });
    }
};