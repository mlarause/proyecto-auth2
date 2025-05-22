const authJwt = require('./authJwt');
const verifySignUp = require('./verifySignUp');
const role = require('./role');
// Importa otros middlewares si los tienes (ej: auth.js, verifySupplier.js)

module.exports = {
  authJwt: require('./authJwt'),
  verifySignUp: require('./verifySignUp'),
  role: require('./role')
};