const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  // Obtener token de múltiples fuentes
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extraer el token del header 'Bearer token'
  
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
    
    // Asignar información del usuario al request
    req.user = {
      id: decoded.id,
      role: decoded.role
    };
    next();
  });
};