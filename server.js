require('dotenv').config(); 

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library'); 

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;


//Verificar OAth2 para Google(Tokens)

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

//MiddleWare
app.use(express.json());

//Conexion a MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})

.then(() => console.log('MongoDB conectado exitosamente'))
.catch(err => console.error('Error de conexión a MongoDB:', err));

//Esquema Modelo de usuario (Mongoose)
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false }, 
    googleId: { type: String, required: false, unique: true }, 
    username: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

//Middleware - autenticacion - ruta protegida
const protect = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'No hay token, autorización denegada' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token no válido' });
    }
};

// Rutas de autenticación

// 1. Registro (Email y Contraseña)

app.post('/api/auth/register', async (req, res) => {
    const { email, password, username } = req.body;
    if (!email || !password || !username) {
        return res.status(400).json({ message: 'Por favor, introduce todos los campos requeridos' });
    }

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'El usuario ya existe' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({
            email,
            password: hashedPassword,
            username
        });

        await user.save();

        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            userId: user.id,
            accessToken: token,
            username: user.username,
            message: 'Usuario registrado exitosamente'
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error del servidor');
    }
});

// 2. Login (Email y Contraseña)

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, introduce correo y contraseña' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Credenciales inválidas' });
        }
        if (!user.password) {
            return res.status(400).json({ message: 'Este correo está registrado con Google. Por favor, usa el login de Google.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciales inválidas' });
        }

        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            userId: user.id,
            accessToken: token,
            username: user.username,
            message: 'Login exitoso'
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error del servidor');
    }
});

// 3. Login con Google

app.post('/api/auth/google-login', async (req, res) => {
    const { idToken } = req.body; 

    if (!idToken) {
        return res.status(400).json({ message: 'ID Token de Google es requerido' });
    }

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: idToken,
            //MI ID DE CLIENTE DE GOOGLE
            audience: 75282745771-197vm5m67kuec92bj5o22ju2bf2ap4kl.apps.googleusercontent.com, 
        });
        const payload = ticket.getPayload();
        const googleId = payload['sub']; 
        const email = payload['email'];
        const username = payload['name'] || email; 



        let user = await User.findOne({ googleId: googleId });

        if (user) {

            const jwtPayload = { user: { id: user.id } };
            const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });
            return res.json({
                userId: user.id,
                accessToken: token,
                username: user.username,
                message: 'Login con Google exitoso (usuario existente)'
            });
        }

        user = await User.findOne({ email: email });

        if (user) {
            
            user.googleId = googleId;
            await user.save();
            const jwtPayload = { user: { id: user.id } };
            const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });
            return res.json({
                userId: user.id,
                accessToken: token,
                username: user.username,
                message: 'Cuenta existente vinculada con Google'
            });
        }

        // Si usuario no existe - crear nuevo usuario
        user = new User({
            email: email,
            username: username,
            googleId: googleId,
            password: null 
        });

        await user.save();

        const jwtPayload = { user: { id: user.id } };
        const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            userId: user.id,
            accessToken: token,
            username: user.username,
            message: 'Nuevo usuario registrado con Google'
        });

    } catch (err) {
        console.error('Error en Google Login:', err.message);
        res.status(500).json({ message: 'Error al verificar token de Google o al registrar/loguear', error: err.message });
    }
});

//Ruta protegida de ejemplo
app.get('/api/protected', protect, (req, res) => {
    res.json({ message: `Bienvenido usuario ${req.user.id} a la ruta protegida!` });
});

process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('Conexión a MongoDB cerrada por Ctrl+C');
  process.exit(0);
});



app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));