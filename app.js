// Imports
require('dotenv').config()
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")


const app = express()

//Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({msg:'Bem vindo a API'})
});

// Private Route 
app.get('/user/:id', checkToken, async(req, res) => {
    const id = req.params.id

    // check if user exists
    const user =await User.findById(id, '-passowrd')

    if(!User) {
        return res.status(404).json({msg: 'Usuário não encontrado.'})
    }

    res.status(200).json({user})
})

function checkToken(req, res, next) {

    const authHeader = req.Headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'acesso negado!'})
    }

    try {
        
        const secret = process.env.SECRET

        jwt.verify(token, secret)
        next()

    } catch (error) {
        res.status(400).json({msg: 'Token inválido!'})
    }

}

// Credentials 
const dbuser = process.env.DB_USER
const db     = process.env.DB_PASS

// Register USer
app.post('auth/register/', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body

    // Validations
    if(!name) {
        return res.status(422).json({msg: 'O nome é obrigatório! '})
    }
    if(!email) {
        return res.status(422).json({msg: 'O Email é obrigatório! '})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória! '})
    }
    if(password !== confirmpassword) {
        return res.status(422).json({msg: 'As senhas não conferem!'})
    }

    // Checks if user exists
    const userExists = await User.findOne({email: email})

    if(userExists) {
        return res.status(422).json({msg: 'Usuário já cadastrado.'})
    }

    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create User
    const user = new User ({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso'})

    } catch(error) {
        console.log(error)
        
        res.status(500).json({msg: 'Ocorreu um erro no servidor, tente novamente mais tarde!'})
    }
})

// Login User

app.post('/auth/login', async (req, res) => {
    const {email, passowrd} = req.body

    // Validations
    if(!email) {
        return res.status(422).json({msg: 'O Email é obrigatório! '})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória! '})
    }

    // Check if User exists
    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(422).json({msg: 'Usuário não encontrado'})
    }

    // Check if password match
    const checkPassword = await bcrypt.compare(password, user.passowrd)

    if(!checkPassword){
        return res.status(404).json({msg: 'Senha inválida!' })

    }
    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,
        },
        secret,
        )

        res.status(200).json({msg: 'Autenticação realizada com sucesso!', token})

    } catch(error) {
        console.log(error)
        
        res.status(500).json({msg: 'Ocorreu um erro no servidor, tente novamente mais tarde!'})
    }

})

mongoose.connect(`mongodb+srv://${dbuser}:${dbpassword}@cluster0.qz2bu.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(() => {
    app.listen(3000)
    console.log("conectou ao banco")
}).catch((err) => console.log(err))

