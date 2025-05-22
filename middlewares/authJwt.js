const jwt = require('jsonwebtoken');
const config = require('../config/auth.config');

const verifyToken = (req, res, next) => {
    // Obtener token de headers, cookies o query params
    const token = req.headers['x-access-token'] || 
                 req.cookies?.token || 
                 req.query?.token;

    if (!token) {
        console.log('Intento de acceso sin token');
        return res.status(403).json({
            success: false,
            message: 'No se proporcionó token de autenticación'
        });
    }

    try {
        // Verificar y decodificar token
        const decoded = jwt.verify(token, config.secret);
        
        // Verificar que el token contenga información esencial
        if (!decoded.id || !decoded.role) {
            console.error('Token incompleto:', decoded);
            return res.status(401).json({
                success: false,
                message: 'Token inválido (falta información de usuario)'
            });
        }

        // Adjuntar información al request
        req.userId = decoded.id;
        req.userRole = decoded.role;
        req.userEmail = decoded.email;

        console.log(`Acceso autorizado para: ${decoded.email} (${decoded.role})`);
        next();

    } catch (error) {
        console.error('Error al verificar token:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Token inválido o expirado'
        });
    }
};

module.exports = {
    verifyToken
};