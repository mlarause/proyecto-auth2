const db = require("../models");
const User = db.user;

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.status(200).send(users);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).send({ message: "Usuario no encontrado." });
    }
    res.status(200).send(user);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    ).select('-password');
    
    if (!updatedUser) {
      return res.status(404).send({ message: "Usuario no encontrado." });
    }
    
    res.status(200).send(updatedUser);
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const deletedUser = await User.findByIdAndDelete(req.params.id);
    if (!deletedUser) {
      return res.status(404).send({ message: "Usuario no encontrado." });
    }
    res.status(200).send({ message: "Usuario eliminado exitosamente." });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};