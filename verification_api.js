// To run this file, you need to install the required packages:
// npm install express mongoose uuid dotenv

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

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
    status: { type: String, default: 'active' } // 'active' or 'used'
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

        // Check for duplicate emails in DB
        const emails = ticketHolders.map(holder => holder.email);
        const existingUsers = await User.find({ email: { $in: emails } });

        if (existingUsers.length > 0) {
            const duplicateEmails = existingUsers.map(user => user.email);
            return res.status(409).json({
                error: `Duplicate email(s) found: ${duplicateEmails.join(', ')}. Tickets not generated.`
            });
        }

        const tickets = [];

        for (const holder of ticketHolders) {
            const ticketId = uuidv4();

            const newUser = new User({
                id: ticketId,
                name: holder.name,
                email: holder.email,
                phone: holder.phone,
                status: 'active'
            });

            await newUser.save();

            tickets.push({
                id: ticketId,
                name: holder.name,
                email: holder.email,
                phone: holder.phone,
                status: 'active'
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
        const user = await User.findOne({ id: id });

        if (!user) {
            return res.status(404).json({
                status: 'not-found',
                message: 'Ticket not found.'
            });
        }

        if (user.status !== 'active') {
            return res.status(200).json({
                status: 'used',
                message: 'This ticket has already been used.'
            });
        }

        // First-time verification → update status to "used"
        user.status = 'used';
        await user.save();

        return res.status(200).json({
            status: 'authentic',
            data: { name: user.name, email: user.email, phone: user.phone }
        });

    } catch (error) {
        console.error('Database query error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An internal server error occurred.'
        });
    }
});

// server listening
app.listen(port, () => {
    console.log(`✅ Verification API listening at http://localhost:${port}`);
    console.log(`👉 Open http://localhost:${port}/admin.html to generate tickets`);
    console.log(`👉 Open http://localhost:${port}/index.html to verify a ticket`);
});
