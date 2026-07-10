const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware Configuration
app.use(cors());
app.use(express.json());

// PostgreSQL Database Connection Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Render sets this environment variable automatically
    ssl: {
        rejectUnauthorized: false
    }
});

// Database Initialization (Make sure the tables exist)
const initDb = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                phone_number VARCHAR(50) UNIQUE,
                gender VARCHAR(50),
                bio TEXT,
                secret_answer TEXT NOT NULL,
                profile_pic_url TEXT
            );

            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                liker_id INT REFERENCES users(id) ON DELETE CASCADE,
                liked_id INT REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(liker_id, liked_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INT REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
                message_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("Database tables checked/created successfully.");
    } catch (err) {
        console.error("Database initialization failed:", err);
    }
};
initDb();

// 1. SIGNUP ROUTE (With fix for optional unique phone numbers)
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password, name, username, phone_number, gender, bio, secretAnswer } = req.body;

        if (!email || !password || !name || !username || !secretAnswer) {
            return res.status(400).json({ error: "Missing required fields." });
        }

        // CRITICAL DATABASE FIX: Convert empty/blank text strings into explicit JavaScript null values
        // This stops PostgreSQL from throwing a 23505 unique constraint duplicate check failure on empty strings.
        const finalPhoneNumber = (phone_number && phone_number.trim() !== "") ? phone_number.trim() : null;

        const query = `
            INSERT INTO users (email, password, name, username, phone_number, gender, bio, secret_answer)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, email, name, username;
        `;
        const values = [
            email.toLowerCase().trim(), 
            password, 
            name.trim(), 
            username.toLowerCase().trim(), 
            finalPhoneNumber, 
            gender, 
            bio, 
            secretAnswer.trim()
        ];

        const result = await pool.query(query, values);
        res.status(201).json({ message: "Registration successful!", user: result.rows[0] });

    } catch (error) {
        console.error("Signup error details:", error);
        
        // Handle standard key collision errors cleanly without crashing
        if (error.code === '23505') {
            if (error.constraint.includes('username')) {
                return res.status(400).json({ error: "That username is already taken." });
            }
            if (error.constraint.includes('email')) {
                return res.status(400).json({ error: "An account with this email already exists." });
            }
            if (error.constraint.includes('phone_number')) {
                return res.status(400).json({ error: "That phone number is already linked to an account." });
            }
        }
        res.status(500).json({ error: "Internal server error during registration." });
    }
});

// 2. LOGIN ROUTE
app.post('/api/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        if (!identifier || !password) {
            return res.status(400).json({ error: "Missing login parameters." });
        }

        const cleanIdentifier = identifier.toLowerCase().trim();
        const query = `
            SELECT * FROM users 
            WHERE email = $1 OR username = $1 OR phone_number = $1;
        `;
        const result = await pool.query(query, [cleanIdentifier]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "Invalid username, email, or password." });
        }

        const user = result.rows[0];

        // Production warning: Remember to integrate bcrypt hash matching here in the future
        if (user.password !== password) {
            return res.status(401).json({ error: "Invalid username, email, or password." });
        }

        res.status(200).json({
            message: "Login successful!",
            user: { id: user.id, email: user.email, name: user.name, username: user.username }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal server processing error." });
    }
});

// 3. DISCOVER FEED ROUTE
app.get('/api/users/discover', async (req, res) => {
    try {
        const { userId } = req.query;
        if (!userId) return res.status(400).json({ error: "User ID is required." });

        // Select profiles that the current user has not liked yet, excluding themselves
        const query = `
            SELECT id, name, username, bio, profile_pic_url FROM users
            WHERE id != $1 AND id NOT IN (
                SELECT liked_id FROM likes WHERE liker_id = $1
            )
            LIMIT 10;
        `;
        const result = await pool.query(query, [userId]);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to fetch discovery feed profiles." });
    }
});

// 4. SUBMIT A LIKE / MATCH CHECK ROUTE
app.post('/api/like', async (req, res) => {
    try {
        const { likerId, likedId } = req.body;
        if (!likerId || !likedId) return res.status(400).json({ error: "Missing relationship parameters." });

        // Record the new outgoing relationship
        await pool.query(`
            INSERT INTO likes (liker_id, liked_id) 
            VALUES ($1, $2) ON CONFLICT DO NOTHING;
        `, [likerId, likedId]);

        // Check if the recipient has already liked the sender back
        const matchCheck = await pool.query(`
            SELECT * FROM likes 
            WHERE liker_id = $1 AND liked_id = $2;
        `, [likedId, likerId]);

        if (matchCheck.rows.length > 0) {
            return res.status(200).json({ match: true, message: "Mutual match unlocked!" });
        }

        res.status(200).json({ match: false, message: "Like processed." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to record love action." });
    }
});

// 5. FETCH ACTIVE CHAT ROOM MESSAGES
app.get('/api/messages', async (req, res) => {
    try {
        const { userOne, userTwo } = req.query;
        if (!userOne || !userTwo) return res.status(400).json({ error: "Missing chat IDs." });

        const query = `
            SELECT * FROM messages
            WHERE (sender_id = $1 AND receiver_id = $2) 
               OR (sender_id = $2 AND receiver_id = $1)
            ORDER BY created_at ASC;
        `;
        const result = await pool.query(query, [userOne, userTwo]);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to fetch chat logs." });
    }
});

// 6. SEND LIVE MESSAGE ROUTE
app.post('/api/messages', async (req, res) => {
    try {
        const { senderId, receiverId, messageText } = req.body;
        if (!senderId || !receiverId || !messageText) {
            return res.status(400).json({ error: "Cannot process empty message frames." });
        }

        const query = `
            INSERT INTO messages (sender_id, receiver_id, message_text)
            VALUES ($1, $2, $3) RETURNING *;
        `;
        const result = await pool.query(query, [senderId, receiverId, messageText.trim()]);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Message transit loop dropped." });
    }
});

// 7. ACCOUNT RECOVERY PASSWORD RESET ROUTE
app.post('/api/reset-password', async (req, res) => {
    try {
        const { identifier, secretAnswer, newPassword } = req.body;
        if (!identifier || !secretAnswer || !newPassword) {
            return res.status(400).json({ error: "Missing required account information data entries." });
        }

        const cleanIdentifier = identifier.toLowerCase().trim();
        const cleanAnswer = secretAnswer.toLowerCase().trim();

        const query = `
            SELECT * FROM users 
            WHERE email = $1 OR username = $1 OR phone_number = $1;
        `;
        const result = await pool.query(query, [cleanIdentifier]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No matching account entry discovered." });
        }

        const user = result.rows[0];

        if (user.secret_answer.toLowerCase().trim() !== cleanAnswer) {
            return res.status(401).json({ error: "Security question confirmation failed." });
        }

        await pool.query('UPDATE users SET password = $1 WHERE id = $2;', [newPassword, user.id]);
        res.status(200).json({ message: "Password updated successfully!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to reset password details." });
    }
});

app.listen(PORT, () => {
    console.log(`Server executing successfully on port ${PORT}`);
});