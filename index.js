require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); // Pure JS module for absolute cross-platform stability

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware configuration
app.use(cors());
app.use(express.json());

// Database Connection Setup
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Initialize and Migrate Database Tables Dynamically
async function initDB() {
    try {
        // 1. Core Users Table Base Setup
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 2. Combined Robust Migration Checks (Guarantees missing columns are appended safely)
        const alterQueries = [
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS gender VARCHAR(50);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_pic_url TEXT;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS secret_answer TEXT;`
        ];

        for (const query of alterQueries) {
            await pool.query(query);
        }

        // 3. Likes Interaction Table Setup
        await pool.query(`
            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                liker_id INT REFERENCES users(id) ON DELETE CASCADE,
                liked_id INT REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(liker_id, liked_id)
            );
        `);

        // 4. Chat Messages History Table Setup
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INT REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
                message_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Database tables checked, updated, and verified successfully.");
    } catch (err) {
        console.error("Database initialization/migration error:", err);
    }
}
initDB();

/* ================= AUTHENTICATION ENDPOINTS ================= */

// Signup Route (Accepts multi-step flow registration parameters)
app.post('/api/signup', async (req, res) => {
    const { email, password, name, username, phone_number, gender, bio, secretAnswer } = req.body;

    if (!email || !password || !name || !username || !secretAnswer) {
        return res.status(400).json({ error: "All required configuration credentials fields are missing." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Target column mapped cleanly to password_hash to comply with database constraints
        const result = await pool.query(
            `INSERT INTO users (email, password_hash, name, username, phone_number, gender, bio, secret_answer) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, name, username, email`,
            [email.toLowerCase(), hashedPassword, name, username.toLowerCase(), phone_number, gender, bio, secretAnswer]
        );

        res.status(201).json({ message: "User registered successfully", user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: "Email or username already exists in our system." });
        }
        console.error("Signup error details:", err);
        res.status(500).json({ error: "Internal server error during registration." });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ error: "Login identifier and password are required." });
    }

    try {
        const userCheck = await pool.query(
            `SELECT * FROM users WHERE email = $1 OR username = $2 OR phone_number = $3`,
            [identifier.toLowerCase(), identifier.toLowerCase(), identifier]
        );

        if (userCheck.rows.length === 0) {
            return res.status(400).json({ error: "Invalid credentials." });
        }

        const user = userCheck.rows[0];
        // Compare password input safely with the database password_hash records
        const passMatch = await bcrypt.compare(password, user.password_hash);

        if (!passMatch) {
            return res.status(400).json({ error: "Invalid credentials." });
        }

        res.status(200).json({
            message: "Login successful",
            user: { id: user.id, name: user.name, username: user.username, email: user.email }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error during login." });
    }
});

// Password Reset Route
app.post('/api/reset-password', async (req, res) => {
    const { identifier, secretAnswer, newPassword } = req.body;

    if (!identifier || !secretAnswer || !newPassword) {
        return res.status(400).json({ error: "All account recovery fields are required." });
    }

    try {
        const userCheck = await pool.query(
            `SELECT * FROM users WHERE email = $1 OR username = $2 OR phone_number = $3`,
            [identifier.toLowerCase(), identifier.toLowerCase(), identifier]
        );

        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: "Account not found." });
        }

        const user = userCheck.rows[0];

        if (user.secret_answer !== secretAnswer) {
            return res.status(400).json({ error: "Security answer verification failed." });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [hashedNewPassword, user.id]);

        res.status(200).json({ message: "Password updated successfully." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error during password reset." });
    }
});

/* ================= CORE INTERACTION ENDPOINTS ================= */

// Get Discovery Feed Profiles Route
app.get('/api/users/discover', async (req, res) => {
    const { userId } = req.query;

    if (!userId) {
        return res.status(400).json({ error: "User ID parameter is missing." });
    }

    try {
        const discoverProfiles = await pool.query(
            `SELECT id, name, username, bio, profile_pic_url FROM users 
             WHERE id != $1 AND id NOT IN (
                 SELECT liked_id FROM likes WHERE liker_id = $1
             ) ORDER BY RANDOM() LIMIT 10`,
            [userId]
        );

        res.status(200).json(discoverProfiles.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error fetching feed profiles." });
    }
});

// Post Profiles Like/Swipe Interaction Route
app.post('/api/like', async (req, res) => {
    const { likerId, likedId } = req.body;

    if (!likerId || !likedId) {
        return res.status(400).json({ error: "Liker and Liked profiles parameters required." });
    }

    try {
        await pool.query(
            `INSERT INTO likes (liker_id, liked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
            [likerId, likedId]
        );

        const reverseMatchCheck = await pool.query(
            `SELECT * FROM likes WHERE liker_id = $1 AND liked_id = $2`,
            [likedId, likerId]
        );

        const isMatch = reverseMatchCheck.rows.length > 0;
        res.status(200).json({ success: true, match: isMatch });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error recording swipe data parameters." });
    }
});

// Get Room Chat Messages Route
app.get('/api/messages', async (req, res) => {
    const { userOne, userTwo } = req.query;

    if (!userOne || !userTwo) {
        return res.status(400).json({ error: "Chat workspace targets missing." });
    }

    try {
        const conversationHistory = await pool.query(
            `SELECT * FROM messages 
             WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)
             ORDER BY created_at ASC`,
            [userOne, userTwo]
        );

        res.status(200).json(conversationHistory.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error fetching historical messages." });
    }
});

// Post Send Chat Messages Route
app.post('/api/messages', async (req, res) => {
    const { senderId, receiverId, messageText } = req.body;

    if (!senderId || !receiverId || !messageText) {
        return res.status(400).json({ error: "Incomplete target data message inputs." });
    }

    try {
        const sentRecordResult = await pool.query(
            `INSERT INTO messages (sender_id, receiver_id, message_text) 
             VALUES ($1, $2, $3) RETURNING *`,
            [senderId, receiverId, messageText]
        );

        res.status(201).json(sentRecordResult.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error recording message transactional data." });
    }
});

// Start Server Listen Instance
app.listen(PORT, () => {
    console.log(`Server executing successfully on port ${PORT}`);
});