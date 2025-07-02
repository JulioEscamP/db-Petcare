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



// ESQUEMAS DE BASE DE DATOS (ACTUALIZADOS)
// ========================================================================

// Perfil para usuarios normales
const UserProfileSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    edad: { type: String, required: true },
    dui: { type: String, required: true, unique: true },
    telefono: { type: String, required: true },
    direccion: { type: String, required: true },
});
const UserProfile = mongoose.model('UserProfile', UserProfileSchema);

// Perfil para veterinarios
const VetProfileSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    telefono: { type: String, required: true },
    direccion: { type: String, required: true },
    numero_de_registro: { type: String, required: true, unique: true },
});
const VetProfile = mongoose.model('VetProfile', VetProfileSchema);

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false }, // No requerido para login con Google
    googleId: { type: String, required: false, unique: true, sparse: true }, // sparse para permitir nulos únicos
    role: {
        type: String,
        enum: ['user', 'vet'],
        required: true,
        default: 'user'
    },
    // Referencia al perfil especifico segun el rol
    profile: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        refPath: 'roleModel' // Referencia dinámica basada en el campo 'role'
    },
    roleModel: {
        type: String,
        required: true,
        enum: ['UserProfile', 'VetProfile']
    }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);


// Esquema para la request de un servicio (servicio solicitado por user) - Necesito ver estado final de request de servicio

const ServiceRequestSchema = new mongoose.Schema({
    pet: { type: mongoose.Schema.Types.ObjectId, ref: 'Pet', required: true }, // La mascota que solicita el servicio

    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // El dueño de la mascota (usuario que solicita)

    veterinarian: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }, // El veterinario asignado

    serviceType: { type: String, required: true }, 

    preferredDateTime: { type: Date, required: true }, 

    confirmedDateTime: { type: Date, required: false }, 
    status: {
        type: String,
        enum: ['Pending', 'Approved', 'Rejected', 'Cancelled'],
        default: 'Pending'
    },

    notes: { type: String, required: false }, // Notas del dueño

    vetNotes: { type: String, required: false }, // Notas del veterinario
    
}, { timestamps: true });


const ServiceRequest = mongoose.model('ServiceRequest', ServiceRequestSchema);








// 1. Registro de Usuario Normal (Actualizado)
app.post('/api/auth/register', async (req, res) => {
    const { nombre, edad, dui, email, telefono, direccion, password, passwordConfirmation } = req.body;

    // Validacion de campos
    if (!nombre || !email || !password || !passwordConfirmation) {
        return res.status(400).json({ message: 'Por favor, introduce todos los campos requeridos.' });
    }
    if (password !== passwordConfirmation) {
        return res.status(400).json({ message: 'Las contraseñas no coinciden.' });
    }

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
        }

        // Crear el perfil del usuario
        const userProfile = new UserProfile({ nombre, edad, dui, telefono, direccion });
        await userProfile.save();

        // Hashear la contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Crear el usuario principal
        user = new User({
            email,
            password: hashedPassword,
            role: 'user',
            profile: userProfile._id,
            roleModel: 'UserProfile'
        });
        await user.save();

        // Generar token JWT
        const payload = { user: { id: user.id, role: user.role } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            message: 'Usuario registrado exitosamente',
            userId: user.id,
            accessToken: token,
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error del servidor');
    }
});

// Registro de Veterinario
app.post('/api/auth/vet-register', async (req, res) => {
    const { nombre, email, telefono, direccion, numero_de_registro, password, passwordConfirmation } = req.body;

    // Validacion de campos
    if (!nombre || !email || !numero_de_registro || !password || !passwordConfirmation) {
        return res.status(400).json({ message: 'Por favor, introduce todos los campos requeridos.' });
    }
    if (password !== passwordConfirmation) {
        return res.status(400).json({ message: 'Las contraseñas no coinciden.' });
    }

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
        }

        // Crear el perfil del veterinario
        const vetProfile = new VetProfile({ nombre, telefono, direccion, numero_de_registro });
        await vetProfile.save();

        // Hashear la contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Crear el usuario principal con rol 'vet'
        user = new User({
            email,
            password: hashedPassword,
            role: 'vet',
            profile: vetProfile._id,
            roleModel: 'VetProfile'
        });
        await user.save();

        // Generar token JWT
        const payload = { user: { id: user.id, role: user.role } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            message: 'Veterinario registrado exitosamente',
            userId: user.id,
            accessToken: token,
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error del servidor');
    }
});


// 3. Login (Email y Contraseña) - Sin cambios
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

        const payload = { user: { id: user.id, role: user.role } };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            userId: user.id,
            accessToken: token,
            username: user.email 
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
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const googleId = payload['sub'];
        const email = payload['email'];
        const nombre = payload['name'];

        // Caso 1: El usuario ya existe con esta cuenta de Google
        let user = await User.findOne({ googleId }).populate('profile');
        if (user) {
            const jwtPayload = { user: { id: user.id, role: user.role } };
            const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });
            return res.json({
                userId: user.id,
                accessToken: token,
                username: user.profile.nombre,
            });
        }

        // Caso 2: El usuario existe con este email, pero no ha usado Google Sign-in
        user = await User.findOne({ email });
        if (user) {
            user.googleId = googleId;
            await user.save();
            const jwtPayload = { user: { id: user.id, role: user.role } };
            const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });
            return res.json({
                userId: user.id,
                accessToken: token,
                username: user.email, 
            });
        }

        // Caso 3: El usuario es completamente nuevo - Creamos un perfil basico y el usuario principal.
        const newUserProfile = new UserProfile({
            nombre: nombre,
            // La app puede pedirle al usuario que los complete más tarde.
        });
        await newUserProfile.save();

        const newUser = new User({
            email: email,
            googleId: googleId,
            password: null, // Sin contraseña local
            role: 'user',
            profile: newUserProfile._id,
            roleModel: 'UserProfile'
        });
        await newUser.save();

        const jwtPayload = { user: { id: newUser.id, role: newUser.role } };
        const token = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            userId: newUser.id,
            accessToken: token,
            username: nombre,
        });

    } catch (err) {
        console.error('Error en Google Login:', err.message);
        res.status(500).json({ message: 'Error al verificar token de Google', error: err.message });
    }
});




app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));