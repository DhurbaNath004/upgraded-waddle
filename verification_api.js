// To run this file, you need to install the required packages:
// npm install express mongoose uuid dotenv

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT;

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
    email: String,
    phone: String
});

const User = mongoose.model('User', userSchema);

// middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ----- Ticket Generation API -----
// Method: POST
// Route: /api/generate-tickets
app.post('/api/generate-tickets', async (req, res) => {
    try {
        const ticketHolders = req.body.ticketHolders;
        if (!ticketHolders || ticketHolders.length === 0) {
            return res.status(400).json({ error: 'No ticket holders provided.' });
        }

        const tickets = [];

        for (const holder of ticketHolders) {
            const ticketId = uuidv4();

            const newUser = new User({
                id: ticketId,
                name: holder.name,
                email: holder.email,
                phone: holder.phone
            });

            await newUser.save();

            tickets.push({
                id: ticketId,
                name: holder.name,
                email: holder.email,
                phone: holder.phone
            });
        }

        res.status(200).json({
            message: 'Tickets generated successfully.',
            tickets: tickets
        });

    } catch (error) {
        console.error('Error during ticket generation:', error);
        res.status(500).json({ error: 'An internal server error occurred during ticket generation.' });
    }
});

// ----- Ticket Verification API -----
// Method: GET
// Route: /api/verify/:id
app.get('/api/verify/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findOne({ id: id }).lean();

        if (user) {
            res.status(200).json({
                authentic: true,
                data: user
            });
        } else {
            res.status(404).json({
                authentic: false,
                message: 'Ticket not found.'
            });
        }
    } catch (error) {
        console.error('Database query error:', error);
        res.status(500).json({
            authentic: false,
            message: 'An internal server error occurred.'
        });
    }
});

// server listening
app.listen(port, () => {
    console.log(`Verification API listening at http://localhost:${port}`);
    console.log(`Open http://localhost:${port}/admin.html to generate tickets`);
    console.log(`Open http://localhost:${port}/index.html to verify a ticket`);
});
