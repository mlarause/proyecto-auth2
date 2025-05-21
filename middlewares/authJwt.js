const jwt = require('jsonwebtoken');
const config = require('../config/auth.config');
const db = require('../models');

verifyToken = async (req, res, next) => {
  const token = req.headers['x-access-token'];
  
  if (!token) {
    return res.status(403).json({
      success: false,
      message: "No se proporcionó token"
    });
  }

  try {
    const decoded = jwt.verify(token, config.secret);
    const user = await db.user.findById(decoded.id).populate('roles').exec();
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Usuario no encontrado"
      });
    }
    
    req.userId = decoded.id;
    req.userRoles = user.roles.map(role => role.name);
    next();
  } catch (error) {
    console.error('Error en verifyToken:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: "Token expirado"
      });
    }
    
    return res.status(401).json({
      success: false,
      message: "Token inválido"
    });
  }
};

isAdmin = (req, res, next) => {
  if (req.userRoles && req.userRoles.includes('admin')) {
    return next();
  }
  res.status(403).json({
    success: false,
    message: "Se requieren privilegios de administrador"
  });
};

checkRoles = (allowedRoles) => {
  return (req, res, next) => {
    if (req.userRoles && req.userRoles.some(role => allowedRoles.includes(role))) {
      return next();
    }
    res.status(403).json({
      success: false,
      message: "No tienes los permisos necesarios"
    });
  };
};

module.exports = {
  verifyToken,
  isAdmin,
  checkRoles
};