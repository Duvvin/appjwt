const mongoose = require('mongoose')
const User = mongoose.model('User', {
    nome: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    senha: {
        type: String,
        required: true
    }
})

module.exports = (User)