const jwt = require('jsonwebtoken');
const config = require('../config');

exports.verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ 
      success: false,
      message: 'Token no proporcionado' 
    });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, config.SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ 
        success: false,
        message: 'Token inválido' 
      });
    }
    
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};