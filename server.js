require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const supplierRoutes = require('./routes/supplierRoutes');

const app = express();

// Configuración mejorada de CORS
const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use('/api/suppliers', supplierRoutes);

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.urlencoded({ extended: true }));

// Conexión a MongoDB actualizada (sin opciones obsoletas)
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/tecnosuministros")
  .then(() => console.log("✅ Conectado a MongoDB"))
  .catch(err => {
    console.error("❌ Error de conexión a MongoDB:", err);
    process.exit(1);
  });

// Importación dinámica de rutas
const routes = [
  { path: '/api/auth', file: './routes/authRoutes' },
  { path: '/api/users', file: './routes/userRoutes' },
  { path: '/api/categories', file: './routes/categoryRoutes' },
  { path: '/api/subcategories', file: './routes/subcategoryRoutes' },
  { path: '/api/products', file: './routes/productRoutes' },
  { path: '/api/suppliers', file: './routes/supplierRoutes' }
];

routes.forEach(route => {
  try {
    const router = require(route.file);
    app.use(route.path, router);
    console.log(`🛣️  Ruta montada: ${route.path}`);
  } catch (err) {
    console.error(`⚠️  Error cargando ruta ${route.file}:`, err.message);
  }
});

// Ruta básica
app.get("/", (req, res) => {
  res.json({ 
    message: "Bienvenido a TecnoSuministros S.A.",
    api_docs: process.env.API_DOCS_URL || "http://localhost:3000/api-docs"
  });
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error('🔥 Error:', err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});