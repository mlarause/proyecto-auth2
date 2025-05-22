const checkRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.userRole) {
      console.error("Intento de verificar rol sin token válido");
      return res.status(500).json({
        success: false,
        message: "Error al verificar rol"
      });
    }

    if (!allowedRoles.includes(req.userRole)) {
      console.log(`Acceso denegado para rol ${req.userRole} en ruta ${req.path}`);
      return res.status(403).json({
        success: false,
        message: "No tienes permisos para esta acción"
      });
    }

    next();
  };
};

// Funciones específicas por rol
const isAdmin = (req, res, next) => {
  return checkRole('admin')(req, res, next);
};

const isCoordinator = (req, res, next) => {
  return checkRole('coordinator')(req, res, next);
};

const isAuxiliary = (req, res, next) => {
  return checkRole('auxiliary')(req, res, next);
};

module.exports = {
  checkRole,
  isAdmin,
  isCoordinator,
  isAuxiliary
};