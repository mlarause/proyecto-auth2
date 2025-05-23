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
  if (req.body.roles && Array.isArray(req.body.roles)) {  // Verificación más robusta
    console.log('[verifySignUp] Verificando roles:', req.body.roles);  // Log para diagnóstico
    
    const validRoles = ['admin', 'coordinador', 'auxiliar'];
    const invalidRoles = req.body.roles.filter(role => !validRoles.includes(role));
    
    if (invalidRoles.length > 0) {
      console.log('[verifySignUp] Roles inválidos detectados:', invalidRoles);  // Log para diagnóstico
      return res.status(400).json({
        success: false,
        message: `Error: Los siguientes roles no existen: ${invalidRoles.join(', ')}`
      });
    }
  } else if (req.body.roles) {
    console.log('[verifySignUp] Formato inválido de roles:', req.body.roles);  // Log para diagnóstico
    return res.status(400).json({
      success: false,
      message: 'Error: El campo roles debe ser un array'
    });
  }
  next();
};

module.exports = {
  checkDuplicateUsernameOrEmail,
  checkRolesExisted
};