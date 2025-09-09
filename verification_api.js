// To run this file, you need to install the required packages:
// npm install express mongoose uuid dotenv

require('dotenv').config();
// To run this file, you need to install the required packages:
// npm install express mongoose uuid dotenv

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 3000;

// ----- Database Configuration (MongoDB Atlas) -----
const mongoURI = process.env.MONGO_URI;

// connect to MongoDB
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ----- Define Schema -----
const userSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    name: String,
    email: { type: String, required: true, unique: true },
    phone: String,
    status: { type: String, default: 'active' },
    type: { type: String, default: 'Regular' },
    class: { type: String, required: true } // Add this line
});

const User = mongoose.model('User', userSchema);
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const Admin = mongoose.model('Admin', adminSchema);

// middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ----- authentication middleware -----
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication token missing.' });
    if (token !== 'secret-admin-token') { // This token should be kept secret
        return res.status(403).json({ message: 'Invalid token.' });
    }
    next();
};
// ----- Login API Endpoint -----
// Method: POST
// Route: /api/login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const adminUser = await Admin.findOne({ username });

        if (!adminUser) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
        
        // Compare the plain text password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, adminUser.password);

        if (isMatch) {
            res.status(200).json({ message: 'Login successful.', token: 'secret-admin-token' });
        } else {
            res.status(401).json({ message: 'Invalid username or password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});


// ----- Ticket Generation API Endpoint -----
// Method: POST
// Route: /api/generate-tickets
app.post('/api/generate-tickets', authenticateToken, async (req, res) => {
    try {
        const { ticketHolders } = req.body;
        const results = [];
        for (const holder of ticketHolders) {
            // Check if email already exists
            const exists = await User.findOne({ email: holder.email });
            if (exists) {
                results.push({ email: holder.email, status: 'duplicate' });
                continue;
            }
            const newUser = new User({
                id: uuidv4(),
                name: holder.name,
                email: holder.email,
                phone: holder.phone,
                class: holder.class,
                type: holder.type,
                status: 'active'
            });
            await newUser.save();
            results.push({ email: holder.email, status: 'created' });
        }
        res.status(200).json({
            message: 'Ticket generation completed.',
            results
        });
    } catch (error) {
        console.error('Error generating tickets:', error);
        res.status(500).json({ error: 'Failed to generate tickets' });
    }
});

// ----- View All Tickets API Endpoint -----
// Method: GET
// Route: /api/tickets
app.get('/api/tickets', authenticateToken, async (req, res) => {
    try {
        const tickets = await User.find({}).sort({ name: 1 });
        res.status(200).json({ tickets: tickets.map(t => ({ id: t.id, name: t.name, email: t.email, phone: t.phone, type: t.type, class: t.class, status: t.status })) });
    } catch (error) {
        console.error('Error fetching tickets:', error);
        res.status(500).json({ message: 'An internal server error occurred while fetching tickets.' });
    }
});


// ----- Ticket Verification API Endpoint -----
// Method: GET
// Route: /api/verify/:id
app.get('/api/verify/:id', async (req, res) => {
    try {
        const ticket = await User.findOne({ id: req.params.id });
        if (!ticket) {
            return res.status(404).json({ status: 'not-found' });
        }

        // If ticket exists but has been used
        if (ticket.status === 'used') {
            return res.status(200).json({ status: 'used' });
        }

        // Valid ticket found
        return res.status(200).json({
            status: 'authentic',
            data: {
                name: ticket.name,
                email: ticket.email,
                phone: ticket.phone,
                class: ticket.class, // Make sure class is included
                type: ticket.type
            }
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ status: 'error', message: 'Server error' });
    }
});

// ----- Reset Ticket API Endpoint -----
// Method: POST
// Route: /api/reset-ticket/:id
app.post('/api/reset-ticket/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findOne({ id });

        if (!user) {
            return res.status(404).json({ message: 'Ticket not found.' });
        }

        if (user.status === 'active') {
            return res.status(400).json({ message: 'Ticket is already active.' });
        }

        user.status = 'active';
        await user.save();

        res.status(200).json({ message: 'Ticket has been reset and is now active again.' });
    } catch (error) {
        console.error('Error resetting ticket:', error);
        res.status(500).json({ message: 'An internal server error occurred while resetting the ticket.' });
    }
});
// ----- Delete Ticket API Endpoint -----
// Method: DELETE
// Route: /api/delete-ticket/:id
app.delete('/api/delete-ticket/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await User.deleteOne({ id });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'Ticket not found.' });
        }

        res.status(200).json({ message: 'Ticket deleted successfully.' });

    } catch (error) {
        console.error('Error deleting ticket:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

const ticketOptions = [
    'Junior',
    'Senior'
];

// server listening
app.listen(port, () => {
    console.log(`✅ Verification API listening at http://localhost:${port}`);
    console.log(`👉 Open http://localhost:${port}/login.html to access admin dashboard`);
    console.log(`👉 Open http://localhost:${port}/index.html to verify a ticket`);
});
