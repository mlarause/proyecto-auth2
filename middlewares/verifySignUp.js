const User = require('../models/User');

const checkDuplicateUsernameOrEmail = async (req, res, next) => {
  try {
    const user = await User.findOne({
      $or: [
        { username: req.body.username },
        { email: req.body.email }
      ]
    }).exec();

    if (user) {
      return res.status(400).json({ 
        success: false,  // Añadido para consistencia
        message: 'Error: Usuario o email ya existen!'
      });
    }
    next();
  } catch (err) {
    console.error('[verifySignUp] Error en checkDuplicateUsernameOrEmail:', err);  // Mejor logging
    res.status(500).json({ 
      success: false,  // Añadido para consistencia
      message: 'Error al verificar credenciales',
      error: err.message 
    });
  }
};

const checkRolesExisted = (req, res, next) => {
  if (req.body.roles && Array.isArray(req.body.roles)) {
    const validRoles = ['admin', 'coordinador', 'auxiliar'];
    const invalidRoles = req.body.roles.filter(role => !validRoles.includes(role));
    
    if (invalidRoles.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Roles inválidos: ${invalidRoles.join(', ')}`
      });
    }
    
    // Convertir array de roles a string para compatibilidad
    req.body.role = req.body.roles[0]; // Tomar el primer rol
    delete req.body.roles; // Eliminar el campo plural
  }
  next();
};
module.exports = {
  checkDuplicateUsernameOrEmail,
  checkRolesExisted
};