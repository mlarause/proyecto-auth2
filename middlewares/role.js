exports.checkRole = (allowedRoles) => {
  return (req, res, next) => {
    console.log('[ROLE] Usuario en request:', req.user); // Diagnóstico
    
    if (!req.user?.role) {
      console.error('[ROLE] Error: Rol no definido en token');
      return res.status(401).json({
        success: false,
        message: 'Token no contiene información de roles'
      });
    }

    if (req.user.role === 'admin') return next(); // Admin tiene acceso completo

    if (!allowedRoles.includes(req.user.role)) {
      console.error('[ROLE] Error: Rol no autorizado', req.user.role);
      return res.status(403).json({
        success: false,
        message: `Requiere uno de estos roles: ${allowedRoles.join(', ')}`
      });
    }

    next();
  };
};