module.exports = {
  secret: process.env.JWT_SECRET || "tusecretoparalostokens",
  jwtExpiration: 86400, // 24 horas en segundos
  jwtRefreshExpiration: 604800, // 7 días en segundos
};
