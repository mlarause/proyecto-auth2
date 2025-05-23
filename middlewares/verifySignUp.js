const User = require('../models/User'); // Importación directa

exports.checkDuplicateUsernameOrEmail = async (req, res, next) => {
  try {
    // Verificar username
    const usernameExists = await User.findOne({ username: req.body.username });
    if (usernameExists) {
      return res.status(400).json({
        success: false,
        message: "El nombre de usuario ya está en uso"
      });
    }

    // Verificar email
    const emailExists = await User.findOne({ email: req.body.email });
    if (emailExists) {
      return res.status(400).json({
        success: false,
        message: "El email ya está registrado"
      });
    }

    next();
  } catch (error) {
    console.error('Error en verificación:', error);
    res.status(500).json({
      success: false,
      message: "Error al verificar credenciales"
    });
  }
};

// ... resto del código ...

const checkRolesExisted = (req, res, next) => {
  if (req.body.roles) {
    const validRoles = ['admin', 'coordinador', 'auxiliar'];
    for (const role of req.body.roles) {
      if (!validRoles.includes(role)) {
        return res.status(400).send({
          message: `Error: El rol ${role} no existe!`
        });
      }
    }
  }
  next();
};

// Exportación como objeto
module.exports = {
  checkDuplicateUsernameOrEmail,
  checkRolesExisted
};