const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  // Obtener token de headers, cookies o query params
  const token = req.headers['x-access-token'] || 
               req.headers['authorization']?.replace('Bearer ', '') || 
               req.cookies?.token || 
               req.query?.token;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token de autenticación no proporcionado'
    });
  }

  // Verificar token
  jwt.verify(token, config.SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        success: false,
        message: 'Token inválido o expirado'
      });
    }
    
    // Asignar usuario al request
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};