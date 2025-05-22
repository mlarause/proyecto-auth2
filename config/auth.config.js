require('dotenv').config();

module.exports = {
    secret: process.env.AUTH_SECRET || 'clave-secreta-desarrollo-123',
    jwtExpiration: process.env.JWT_EXPIRATION || 86400, // 24 horas en segundos
    saltRounds: process.env.SALT_ROUNDS || 8
};