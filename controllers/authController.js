const jwt = require('jsonwebtoken');
const config = require('../config');
const User = require('../models/User');
const bcrypt = require('bcryptjs');

exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Buscar usuario
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // 2. Validar contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    // 3. Generar token CON EL ROL INCLUIDO
    const token = jwt.sign(
      {
        id: user._id,
        role: user.role // ¡ESTE ES EL CAMPO CRÍTICO QUE FALTABA!
      },
      config.SECRET,
      { expiresIn: config.TOKEN_EXPIRATION }
    );

    // 4. Responder con token y datos de usuario
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error en el servidor',
      error: error.message
    });
  }
};

exports.signup = async (req, res) => {
  try {
    const { username, email, password, role = 'auxiliar' } = req.body;

    // 1. Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'El email ya está registrado'
      });
    }

    // 2. Crear nuevo usuario
    const newUser = new User({
      username,
      email,
      password: await bcrypt.hash(password, 10),
      role
    });

    // 3. Guardar usuario
    const savedUser = await newUser.save();

    // 4. Generar token CON EL ROL
    const token = jwt.sign(
      {
        id: savedUser._id,
        role: savedUser.role // ¡INCLUIR EL ROL!
      },
      config.SECRET,
      { expiresIn: config.TOKEN_EXPIRATION }
    );

    // 5. Responder
    res.status(201).json({
      success: true,
      message: 'Usuario registrado exitosamente',
      token,
      user: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email,
        role: savedUser.role
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