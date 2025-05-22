const db = require("../models");
const User = db.user;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");

exports.signin = async (req, res) => {
  try {
    // 1. Validar entrada
    if (!req.body.email || !req.body.password) {
      console.log("Faltan credenciales");
      return res.status(400).json({
        success: false,
        message: "Email y contraseña son requeridos"
      });
    }

    // 2. Buscar usuario (incluyendo solo usuarios activos)
    const user = await User.findOne({ 
      email: req.body.email,
      status: true 
    }).exec();

    if (!user) {
      console.log(`Usuario no encontrado o inactivo: ${req.body.email}`);
      return res.status(401).json({
        success: false,
        message: "Credenciales inválidas"
      });
    }

    // 3. Validar contraseña
    const passwordIsValid = bcrypt.compareSync(
      req.body.password,
      user.password
    );

    if (!passwordIsValid) {
      console.log(`Contraseña incorrecta para usuario: ${req.body.email}`);
      return res.status(401).json({
        success: false,
        message: "Credenciales inválidas"
      });
    }

    // 4. Generar token con información completa
    const token = jwt.sign(
      {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      config.secret,
      {
        expiresIn: config.jwtExpiration
      }
    );

    // 5. Responder con éxito
    console.log(`Login exitoso para usuario: ${user.email} (${user.role})`);
    return res.status(200).json({
      success: true,
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      accessToken: token
    });

  } catch (error) {
    console.error("Error en signin:", error);
    return res.status(500).json({
      success: false,
      message: "Error interno del servidor"
    });
  }
};

exports.signup = async (req, res) => {
  try {
    // Validar campos requeridos
    if (!req.body.name || !req.body.email || !req.body.password) {
      return res.status(400).json({
        success: false,
        message: "Nombre, email y contraseña son requeridos"
      });
    }

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email: req.body.email }).exec();
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "El email ya está registrado"
      });
    }

    // Crear nuevo usuario
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 8),
      role: req.body.role || "auxiliary",
      status: true
    });

    await user.save();

    return res.status(201).json({
      success: true,
      message: "Usuario registrado exitosamente"
    });

  } catch (error) {
    console.error("Error en signup:", error);
    return res.status(500).json({
      success: false,
      message: "Error al registrar usuario"
    });
  }
};