const mongoose = require("mongoose");
const { DB_URI } = require("./config");

const connectDB = async () => {
  try {
    await mongoose.connect(DB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB conectado");
  } catch (err) {
    console.error("❌ Error de conexión a MongoDB:", err.message);
    process.exit(1);
  }
};

module.exports = connectDB;