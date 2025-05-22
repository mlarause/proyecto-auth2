const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  // 1. Obtener token de múltiples fuentes
  let token = req.headers['x-access-token'] || 
             req.headers['authorization'] || 
             req.cookies?.token;

  // 2. Verificar existencia del token
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Acceso denegado: Token no proporcionado'
    });
  }

  // 3. Limpiar token si viene con 'Bearer'
  if (token.startsWith('Bearer ')) {
    token = token.slice(7, token.length);
  }

  // 4. Verificar token
  jwt.verify(token, config.SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        success: false,
        message: 'Token inválido o expirado',
        error: err.name === 'TokenExpiredError' ? 'Token expirado' : 'Token inválido'
      });
    }

    // 5. Asignar información del usuario al request
    req.user = {
      id: decoded.id,
      role: decoded.role
    };
    
    next();
  });
};