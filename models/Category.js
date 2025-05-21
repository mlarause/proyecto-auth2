const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'El nombre es obligatorio'],
    unique: true,
    trim: true
  },
  description: {
    type: String,
    required: [true, 'La descripción es obligatoria'],
    trim: true
  }
}, {
  timestamps: true,
  versionKey: false
});

// Eliminar índice problemático si existe
categorySchema.pre('save', async function(next) {
  try {
    const collection = this.constructor.collection;
    const indexes = await collection.indexes();
    
    // Buscar y eliminar índice problemático con nombre "nombre_1"
    const problematicIndex = indexes.find(index => index.name === 'nombre_1');
    if (problematicIndex) {
      await collection.dropIndex('nombre_1');
    }
  } catch (err) {
    // Ignorar si el índice no existe
    if (!err.message.includes('index not found')) {
      return next(err);
    }
  }
  next();
});

// Crear nuevo índice correcto
categorySchema.index({ name: 1 }, { 
  unique: true,
  name: 'name_1' // Nombre explícito para el índice
});

module.exports = mongoose.model('Category', categorySchema);