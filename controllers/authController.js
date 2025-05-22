const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { verifySignUp } = require('../middlewares');

exports.signup = async (req, res) => {
  try {
    // Validar existencia de usuario/email
    await verifySignUp.checkDuplicateUsernameOrEmail(req, res, async () => {
      await verifySignUp.checkRolesExisted(req, res, async () => {
        const { username, email, password, role } = req.body;

        // Crear usuario con contraseña encriptada
        const user = new User({
          username,
          email,
          password: await bcrypt.hash(password, 10),
          role: role || 'auxiliar' // Valor por defecto
        });

        const savedUser = await user.save();

        // Generar token con el rol incluido
        const token = jwt.sign(
          { 
            id: savedUser._id, 
            role: savedUser.role // Incluir el rol aquí
          },
          config.SECRET,
          { expiresIn: config.TOKEN_EXPIRATION }
        );

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
      });
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

    // Buscar usuario
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    // Validar contraseña
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({
        success: false,
        message: 'Contraseña incorrecta'
      });
    }

    // Generar token con el rol incluido
    const token = jwt.sign(
      { 
        id: user._id, 
        role: user.role // Incluir el rol aquí
      },
      config.SECRET,
      { expiresIn: config.TOKEN_EXPIRATION }
    );

    res.status(200).json({
      success: true,
      message: 'Inicio de sesión exitoso',
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
      message: 'Error al iniciar sesión',
      error: error.message
    });
  }
};

// Opcional: Refrescar token
exports.refreshToken = async (req, res) => {
  try {
    const oldToken = req.headers['authorization']?.split(' ')[1];
    
    if (!oldToken) {
      return res.status(400).json({
        success: false,
        message: 'Token no proporcionado'
      });
    }

    // Verificar token antiguo (ignorando expiración)
    const decoded = jwt.verify(oldToken, config.SECRET, { ignoreExpiration: true });
    
    // Generar nuevo token con el mismo rol
    const newToken = jwt.sign(
      { 
        id: decoded.id, 
        role: decoded.role // Mantener el mismo rol
      },
      config.SECRET,
      { expiresIn: config.TOKEN_EXPIRATION }
    );

    res.status(200).json({
      success: true,
      message: 'Token refrescado exitosamente',
      token: newToken
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      message: 'Error al refrescar token',
      error: error.message
    });
  }
};