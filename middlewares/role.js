exports.checkRole = (allowedRoles = []) => {
  return (req, res, next) => {
    if (!req.userRole) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no autenticado'
      });
    }

    // Admin tiene acceso completo
    if (req.userRole === 'admin') return next();

    // Verificar si el rol está permitido
    if (!allowedRoles.includes(req.userRole)) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para esta acción'
      });
    }

    next();
  };
};