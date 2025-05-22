const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  // Obtener token de múltiples fuentes
  const token = req.headers['x-access-token'] || 
               req.headers['authorization']?.split(' ')[1] || 
               req.cookies?.token;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Acceso no autorizado: Token no proporcionado'
    });
  }

  jwt.verify(token, config.SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        success: false,
        message: 'Token inválido o expirado'
      });
    }

    // Asignar usuario decodificado
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};