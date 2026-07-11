require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); 
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 10000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "716592672743-3866rn9h0p3le4kb6klehhjm9gf9pmh8.apps.googleusercontent.com";
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(cors());
app.use(express.json({ limit: '10mb' })); // Increased limit to handle base64 cropped previews safely

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function initDB() {
    try {
        // Users base structure
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Apply migrations dynamically
        const alterQueries = [
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);`,
            `ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;`, 
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS gender VARCHAR(50);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS location VARCHAR(255);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS relationship_goal VARCHAR(100);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS interests TEXT;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS looking_for VARCHAR(50);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_visible BOOLEAN DEFAULT TRUE;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_pic_url TEXT;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR(255);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255);`
        ];

        for (const query of alterQueries) {
            await pool.query(query);
        }

        // Likes table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                liker_id INT REFERENCES users(id) ON DELETE CASCADE,
                liked_id INT REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(liker_id, liked_id)
            );
        `);

        // Messages table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INT REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
                message_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Database initialized and structural fields updated successfully.");
    } catch (err) {
        console.error("Database initialization error:", err);
    }
}
initDB();

/* AUTHENTICATION ROUTING */

app.post('/api/signup', async (req, res) => {
    const { email, password, name, username } = req.body;
    if (!email || !password || !name || !username) {
        return res.status(400).json({ error: "Required signup fields missing." });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const token = Math.random().toString(36).substring(2, 15);
        
        const result = await pool.query(
            `INSERT INTO users (email, password_hash, name, username, verification_token, is_verified) 
             VALUES ($1, $2, $3, $4, $5, false) RETURNING id, name, username, email`,
            [email.toLowerCase().trim(), hashedPassword, name.trim(), username.toLowerCase().trim(), token]
        );

        console.log(`\n--- [EMAIL SIMULATOR] ---\nVerify: ${req.protocol}://${req.get('host')}/api/verify-email?token=${token}\n-------------------------\n`);
        res.status(201).json({ message: "Registered. Verification link generated in console logs.", user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Email or username already in use." });
        res.status(500).json({ error: "Internal registry failure." });
    }
});

app.get('/api/verify-email', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send("Verification token context missing.");
    try {
        const result = await pool.query(`UPDATE users SET is_verified = true, verification_token = null WHERE verification_token = $1 RETURNING id`, [token]);
        if (result.rows.length === 0) return res.status(400).send("Invalid token sequence.");
        res.send("<h1>Email verified. You can log in securely now.</h1>");
    } catch (err) {
        res.status(500).send("Verification processing error.");
    }
});

app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body;
    try {
        const userCheck = await pool.query(`SELECT * FROM users WHERE email = $1 OR username = $2`, [identifier.toLowerCase().trim(), identifier.toLowerCase().trim()]);
        if (userCheck.rows.length === 0) return res.status(400).json({ error: "Invalid credentials." });
        
        const user = userCheck.rows[0];
        if (!user.is_verified) return res.status(400).json({ error: "Confirm email registration first." });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(400).json({ error: "Invalid credentials." });

        res.status(200).json({ message: "Success", user });
    } catch (err) {
        res.status(500).json({ error: "Login operation failed." });
    }
});

/* DISCOVERY FEED & ACTIONS */

app.get('/api/users/discover', async (req, res) => {
    const { userId } = req.query;
    try {
        const feed = await pool.query(
            `SELECT id, name, username, bio, location, gender, relationship_goal, interests, profile_pic_url FROM users 
             WHERE id != $1 AND is_visible = true AND id NOT IN (SELECT liked_id FROM likes WHERE liker_id = $1) 
             ORDER BY RANDOM() LIMIT 10`, [userId]
        );
        res.status(200).json(feed.rows);
    } catch (err) {
        res.status(500).json({ error: "Feed generation error." });
    }
});

app.post('/api/like', async (req, res) => {
    const { likerId, likedId } = req.body;
    try {
        await pool.query(`INSERT INTO likes (liker_id, liked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [likerId, likedId]);
        const match = await pool.query(`SELECT * FROM likes WHERE liker_id = $1 AND liked_id = $2`, [likedId, likerId]);
        res.status(200).json({ success: true, match: match.rows.length > 0 });
    } catch (err) {
        res.status(500).json({ error: "Swipe action logging failed." });
    }
});

app.listen(PORT, () => console.log(`Execution ongoing on port ${PORT}`));