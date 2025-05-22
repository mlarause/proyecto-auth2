exports.checkRole = (allowedRoles = []) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no autenticado'
      });
    }

    // Admin tiene acceso completo a todo
    if (req.user.role === 'admin') {
      return next();
    }

    // Verificar si el rol del usuario está permitido
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Acceso denegado. Requiere rol: ${allowedRoles.join(' o ')}`
      });
    }

    next();
  };
};