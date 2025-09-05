// এই ফাইলটি চালাতে, আপনাকে 'express', 'mysql2', এবং 'uuid' প্যাকেজগুলো ইনস্টল করতে হবে।
// টার্মিনালে এই কমান্ডটি চালান: npm install express mysql2 uuid

const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3000;

// ----- ডেটাবেস কনফিগারেশন -----
const dbConfig = {
    host: '127.0.0.1',
    user: 'root',
    password: '1234@4321', // আপনার MySQL পাসওয়ার্ড এখানে দিন
    database: 'verification_db',
    port: 3307 // আপনার MySQL পোর্ট যদি আলাদা হয় তবে এখানে দিন
};

// middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // public ফোল্ডারে আপনার HTML ফাইলগুলো থাকতে হবে

// ----- টিকিট জেনারেশন API Endpoin -----
// Method: POST
// Route: /api/generate-tickets
app.post('/api/generate-tickets', async (req, res) => {
    let connection;
    try {
        const ticketHolders = req.body.ticketHolders;
        if (!ticketHolders || ticketHolders.length === 0) {
            return res.status(400).json({ error: 'No ticket holders provided.' });
        }

        connection = await mysql.createConnection(dbConfig);
        const tickets = [];

        for (const holder of ticketHolders) {
            const ticketId = uuidv4();
            const sql = 'INSERT INTO users (id, name, email, phone) VALUES (?, ?, ?, ?)';
            const values = [ticketId, holder.name, holder.email, holder.phone];
            await connection.execute(sql, values);
            
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
    } finally {
        if (connection) connection.end();
    }
});

// ----- টিকিট ভেরিফিকেশন API Endpoin -----
// Method: GET
// Route: /api/verify/:id
app.get('/api/verify/:id', async (req, res) => {
    const { id } = req.params;
    let connection;

    try {
        connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute(
            'SELECT id, name, email, phone FROM users WHERE id = ?',
            [id]
        );

        if (rows.length > 0) {
            // টিকিট পাওয়া গেলে ব্যবহারকারীর তথ্য ও একটি authentic স্ট্যাটাস পাঠানো হবে
            res.status(200).json({
                authentic: true,
                data: rows[0]
            });
        } else {
            // টিকিট না পাওয়া গেলে
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
    } finally {
        if (connection) connection.end();
    }
});

// সার্ভার চালু করা হবে
app.listen(port, () => {
    console.log(`Verification API listening at http://localhost:${port}`);
    console.log(`Open http://localhost:${port}/admin.html to generate tickets`);
    console.log(`Open http://localhost:${port}/index.html to verify a ticket`);
});
