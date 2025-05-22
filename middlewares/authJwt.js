const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  console.log('[AUTH] Headers recibidos:', req.headers); // Diagnóstico
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('[AUTH] Token extraído:', token); // Diagnóstico

  if (!token) {
    console.error('[AUTH] Error: Token no proporcionado');
    return res.status(401).json({
      success: false,
      message: 'Token no proporcionado'
    });
  }

  jwt.verify(token, config.SECRET, (err, decoded) => {
    if (err) {
      console.error('[AUTH] Error al verificar token:', err.message); // Diagnóstico
      return res.status(401).json({
        success: false,
        message: 'Token inválido',
        error: err.message
      });
    }
    
    console.log('[AUTH] Token decodificado:', decoded); // Diagnóstico
    req.user = decoded;
    next();
  });
};