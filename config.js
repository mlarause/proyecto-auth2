module.exports = {  
  SECRET: process.env.JWT_SECRET || 'tusecretoparalostokens',
  TOKEN_EXPIRATION: '24h'
};





  /*SECRET: 'tusecretoparalostokens', // DEBE COINCIDIR CON LA USADA AL GENERAR EL TOKEN
  MONGODB_URI: 'mongodb://localhost:27017/proyecto-auth'
};*/