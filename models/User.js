const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

const UserSchema = new Schema({
    name: {
        type: String,
        required: [true, 'El nombre es obligatorio'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'El email es obligatorio'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Email inválido']
    },
    password: {
        type: String,
        required: [true, 'La contraseña es obligatoria'],
        minlength: [6, 'La contraseña debe tener al menos 6 caracteres']
    },
    role: {
        type: String,
        required: true,
        enum: ['admin', 'coordinator', 'auxiliar'],
        default: 'auxiliar'
    },
    status: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true,
    versionKey: false
});

// Método para comparar contraseñas
UserSchema.methods.comparePassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

// Hash de la contraseña antes de guardar
UserSchema.pre('save', function(next) {
    if (!this.isModified('password')) return next();
    this.password = bcrypt.hashSync(this.password, 8);
    next();
});



module.exports = mongoose.model('User', UserSchema);