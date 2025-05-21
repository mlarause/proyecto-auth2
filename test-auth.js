const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/User'); // Asegúrate que la ruta es correcta

async function testAuth() {
  // 1. Conectar a MongoDB
  await mongoose.connect('mongodb://localhost:27017/proyecto-auth');

  // 2. Buscar usuario
  const user = await User.findOne({ username: "admin1" }).select('+password');
  
  if (!user) {
    console.log("Usuario no encontrado");
    return;
  }

  // 3. Comparar contraseñas
  const isMatch = await bcrypt.compare("Admin123", user.password);
  console.log('--------------------------------');
  console.log('Contraseña ingresada:', "Admin123");
  console.log('Hash almacenado:', user.password);
  console.log('Resultado comparación:', isMatch);
  console.log('--------------------------------');

  // 4. Cerrar conexión
  await mongoose.disconnect();
}

testAuth().catch(console.error);