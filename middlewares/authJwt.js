const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");

const verifyToken = (req, res, next) => {
  // Obtener token de headers o cookies
  const token = req.headers["x-access-token"] || 
                req.headers["authorization"]?.split(' ')[1] || 
                req.cookies?.token;

  if (!token) {
    console.log("Intento de acceso sin token");
    return res.status(403).json({
      success: false,
      message: "No se proporcionó token"
    });
  }

  try {
    // Verificar y decodificar token
    const decoded = jwt.verify(token, config.secret);
    
    // Verificar que el token tenga rol
    if (!decoded.role) {
      console.error("Token sin rol:", decoded);
      return res.status(401).json({
        success: false,
        message: "Token no contiene información de rol"
      });
    }

    // Adjuntar información al request
    req.userId = decoded.id;
    req.userRole = decoded.role;
    req.userEmail = decoded.email;

    console.log(`Acceso autorizado para ${decoded.email} (${decoded.role})`);
    next();
  } catch (err) {
    console.error("Error al verificar token:", err.message);
    return res.status(401).json({
      success: false,
      message: "Token inválido o expirado"
    });
  }
};

module.exports = {
  verifyToken
};