const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  // 1. Extraer token
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token no proporcionado'
    });
  }

  // 2. Verificar token
  jwt.verify(token, config.SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        success: false,
        message: 'Token inválido',
        error: err.message
      });
    }
    
    // 3. Asegurarse que el token tenga rol
    if (!decoded.role) {
      return res.status(401).json({
        success: false,
        message: 'Token no contiene información de rol'
      });
    }

    // 4. Adjuntar usuario al request
    req.user = decoded;
    next();
  });
};