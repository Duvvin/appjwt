// Carregando Módulos
    const mongoose = require("mongoose")
    const express = require("express")
    const app = express()
    require("dotenv").config()
    const bcrypt = require("bcryptjs")
    const jwt = require("jsonwebtoken")

// Models
    const User = require('./models/user')

// Config JSON Response
    app.use(express.json())

// Rotas
    // Rota Pública
    app.get('/', (req, res) => {
        res.status(200).json({ msg: 'Bem vindo á API'})
    })
    // Rota Privada
    app.get('/user/:email', checkToken, async(req,res) => {
        const email = req.params.email
        const user = await User.findOne(
    { email: email },
    '-senha'
)

        if(!user) return res.status(404).json({msg: "Usuario nao encontrado"})
        res.status(200).json({ user })
    })

    function checkToken(req, res, next) {
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]
        if(!token) return res.status(404).json({msg: 'Token nao é valido'})

        try {
            const secret = process.env.SECRET
            jwt.verify(token, secret, { expiresIn: '1h' })
            next()
        } catch(err) {
            res.status(401).json({ msg: 'Erro na autenticação'})
        }
    }

    // Registro
    app.post('/register', async (req, res) => {
        const { nome, email, pass, confirmpass } = req.body
    
        if(!nome) return res.status(422).json({ msg: 'Você precisa inserir um nome'})
        if(!email) return res.status(422).json({ msg: 'Você precisa inserir um email'})
        if(!pass) return res.status(422).json({ msg: 'Você precisa inserir uma senha'})
        if(pass != confirmpass) return res.status(422).json({ msg: 'As senhas nao coincidem'})

        const verifyEmail = await User.findOne({email: email}).lean()

        if(verifyEmail) return res.status(422).json({ msg: 'Este email já esta cadastrado no nosso sistema'})

        const salt = await bcrypt.genSalt(12)
        const passHash = await bcrypt.hash(pass, salt)

        const user = new User({
            nome,
            email,
            senha: passHash
        })

        try {
            await user.save()
            res.status(201).json({ msg: "Usuario criado com sucesso" })
        } catch(err) {
            res.status(500).json({
                msg: 'Aconteceu um Erro, tente novamente mais tarde.'
            })
        }
    }
)

// Login
    app.post('/login', async (req, res) => {
    const { email, pass } = req.body

    if(!email) return res.status(422).json({ msg: 'Você precisa inserir um email'})
    if(!pass) return res.status(422).json({ msg: 'Você precisa inserir uma senha'})

    const user = await User.findOne({email: email})
    if(!user) {
        return res.status(422).json({msg: "Usuario nao encontrado"})
    }

    const check = await bcrypt.compare(pass, user.senha)
    if(!check) return res.status(422).json({msg: 'Senha inválida'})

        try {
            const secret = process.env.SECRET

            const token = jwt.sign(
                {
                    id: user._id,
                },
                secret,
            )

            res.status(200).json({msg: "Autenticação feita com sucesso", token})
        } catch(err) {
            console.log(err)
        }
})

// Conectando Banco de dados
    mongoose.connect(`mongodb://localhost:27017`)
            .then(
                app.listen(8089, () => {
    console.log('Servidor Rodando')
})
            ).catch()