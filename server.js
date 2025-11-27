const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/scrolldeeper', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    email: String,
    fullname: String,
    password: String,
    country: String
});

const User = mongoose.model('User', userSchema);

// Register API
app.post('/api/register', async (req, res) => {
    const { email, fullname, password, country } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.json({ success: false, message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, fullname, password: hashedPassword, country });
    await user.save();

    res.json({ success: true });
});

// Login API (UPDATED)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ success: false, message: 'Invalid password' });

    const token = jwt.sign({ id: user._id }, 'secretkey', { expiresIn: '1h' });

    res.json({
        success: true,
        token,
        user: {
            fullname: user.fullname,
            email: user.email,
            country: user.country
        }
    });
});

// Protected Route Example
app.get('/api/dashboard', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, 'secretkey');
        const user = await User.findById(decoded.id);
        res.json({ message: `Welcome ${user.fullname}` });
    } catch (err) {
        res.status(401).json({ message: 'Unauthorized' });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
