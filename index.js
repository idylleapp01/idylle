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
app.use(express.json({ limit: '10mb' })); 

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { 
        rejectUnauthorized: false,
        sslmode: 'verify-full'
    }
});

async function initDB() {
    try {
        // Users base structure table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Synchronize and apply demographic and matching migrations
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
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS birthdate DATE;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS max_distance_km INT DEFAULT 50;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS min_age_pref INT DEFAULT 18;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS max_age_pref INT DEFAULT 99;`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS latitude NUMERIC(9,6);`,
            `ALTER TABLE users ADD COLUMN IF NOT EXISTS longitude NUMERIC(9,6);`
        ];

        for (const query of alterQueries) {
            await pool.query(query);
        }

        // Likes tracking table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS likes (
                id SERIAL PRIMARY KEY,
                liker_id INT REFERENCES users(id) ON DELETE CASCADE,
                liked_id INT REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(liker_id, liked_id)
            );
        `);

        // Mutual matches data table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS matches (
                id SERIAL PRIMARY KEY,
                user_one INT REFERENCES users(id) ON DELETE CASCADE,
                user_two INT REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_one, user_two)
            );
        `);

        // Communication message streams
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INT REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
                message_text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // System icebreakers conversation engine
        await pool.query(`
            CREATE TABLE IF NOT EXISTS icebreakers (
                id SERIAL PRIMARY KEY,
                prompt_text TEXT NOT NULL
            );
        `);

        // Track secondary gallery images for user profiles
        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_photos (
                id SERIAL PRIMARY KEY,
                user_id INT REFERENCES users(id) ON DELETE CASCADE,
                image_url TEXT NOT NULL,
                is_approved BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Ensure indices for advanced querying pipelines are optimized
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_discovery_filters ON users(gender, is_visible);`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_photos_user ON user_photos(user_id);`);

        // Add startup data rows
        const countCheck = await pool.query('SELECT COUNT(*) FROM icebreakers');
        if (parseInt(countCheck.rows[0].count) === 0) {
            await pool.query(`
                INSERT INTO icebreakers (prompt_text) VALUES 
                ('What is your absolute favorite weekend getaway spot?'),
                ('If you could only eat one meal for the rest of your life, what would it be?'),
                ('What is the most adventurous thing you have ever done?');
            `);
        }

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

/* DYNAMIC ADVANCED DISCOVERY ENGINE */

app.get('/api/users/discover', async (req, res) => {
    const { userId, search, gender, goal, interest } = req.query;
    
    try {
        const userPrefs = await pool.query(`SELECT looking_for, gender FROM users WHERE id = $1`, [userId]);
        if (userPrefs.rows.length === 0) return res.status(404).json({ error: "User context not found." });
        
        const currentUser = userPrefs.rows[0];
        let queryParams = [userId];
        let paramCounter = 2;
        
        let sql = `
            SELECT id, name, username, bio, location, gender, relationship_goal, interests, profile_pic_url 
            FROM users 
            WHERE id != $1 
              AND is_visible = true 
              AND id NOT IN (SELECT liked_id FROM likes WHERE liker_id = $1)
        `;

        if (currentUser.looking_for && currentUser.looking_for !== 'Everyone') {
            sql += ` AND gender = $${paramCounter}`;
            queryParams.push(currentUser.looking_for === 'Men' ? 'Male' : 'Female');
            paramCounter++;
        }

        if (search) {
            sql += ` AND (name ILIKE $${paramCounter} OR bio ILIKE $${paramCounter} OR username ILIKE $${paramCounter})`;
            queryParams.push(`%${search}%`);
            paramCounter++;
        }

        if (gender) {
            sql += ` AND gender = $${paramCounter}`;
            queryParams.push(gender);
            paramCounter++;
        }
        
        if (goal) {
            sql += ` AND relationship_goal = $${paramCounter}`;
            queryParams.push(goal);
            paramCounter++;
        }

        if (interest) {
            sql += ` AND interests ILIKE $${paramCounter}`;
            queryParams.push(`%${interest}%`);
            paramCounter++;
        }

        sql += ` ORDER BY RANDOM() LIMIT 20`;

        const feed = await pool.query(sql, queryParams);
        res.status(200).json(feed.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Advanced discovery compilation failure." });
    }
});

app.post('/api/like', async (req, res) => {
    const { likerId, likedId } = req.body;
    try {
        await pool.query(`INSERT INTO likes (liker_id, liked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [likerId, likedId]);
        
        const matchCheck = await pool.query(`SELECT * FROM likes WHERE liker_id = $1 AND liked_id = $2`, [likedId, likerId]);
        let isMatch = matchCheck.rows.length > 0;

        if (isMatch) {
            const u1 = Math.min(likerId, likedId);
            const u2 = Math.max(likerId, likedId);
            await pool.query(`INSERT INTO matches (user_one, user_two) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [u1, u2]);
        }

        res.status(200).json({ success: true, match: isMatch });
    } catch (err) {
        res.status(500).json({ error: "Swipe action logging failed." });
    }
});

/* CHAT MESSAGING AND CAROUSEL ROUTING */

app.get('/api/matches', async (req, res) => {
    const { userId } = req.query;
    try {
        const matches = await pool.query(`
            SELECT m.id AS match_id, u.id AS user_id, u.name, u.profile_pic_url 
            FROM matches m
            JOIN users u ON (u.id = m.user_one OR u.id = m.user_two)
            WHERE (m.user_one = $1 OR m.user_two = $1) AND u.id != $1
            ORDER BY m.created_at DESC
        `, [userId]);
        res.status(200).json(matches.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to grab match list records." });
    }
});

app.get('/api/icebreakers', async (req, res) => {
    try {
        const prompts = await pool.query(`SELECT * FROM icebreakers ORDER BY RANDOM() LIMIT 3`);
        res.status(200).json(prompts.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to pull interactive prompts." });
    }
});

app.get('/api/messages', async (req, res) => {
    const { senderId, receiverId } = req.query;
    try {
        const chatHistory = await pool.query(`
            SELECT id, sender_id, receiver_id, message_text, created_at 
            FROM messages 
            WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)
            ORDER BY created_at ASC
        `, [senderId, receiverId]);
        res.status(200).json(chatHistory.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to sync connection messages." });
    }
});

app.post('/api/messages', async (req, res) => {
    const { senderId, receiverId, messageText } = req.body;
    try {
        const newMessage = await pool.query(`
            INSERT INTO messages (sender_id, receiver_id, message_text) 
            VALUES ($1, $2, $3) RETURNING *
        `, [senderId, receiverId, messageText]);
        res.status(201).json(newMessage.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Failed to submit new text record." });
    }
});

/* MULTI-PHOTO PLATFORM MANAGEMENT */

app.get('/api/users/:id/photos', async (req, res) => {
    const { id } = req.params;
    try {
        const photos = await pool.query(`SELECT id, image_url FROM user_photos WHERE user_id = $1 ORDER BY id ASC`, [id]);
        res.status(200).json(photos.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to load gallery assets." });
    }
});

app.post('/api/users/:id/photos', async (req, res) => {
    const { id } = req.params;
    const { imageUrl } = req.body;
    if (!imageUrl) return res.status(400).json({ error: "Image data missing." });

    try {
        const countCheck = await pool.query(`SELECT COUNT(*) FROM user_photos WHERE user_id = $1`, [id]);
        if (parseInt(countCheck.rows[0].count) >= 5) {
            return res.status(400).json({ error: "Gallery slots full. Delete an image first." });
        }
        const newPhoto = await pool.query(`INSERT INTO user_photos (user_id, image_url) VALUES ($1, $2) RETURNING *`, [id, imageUrl]);
        res.status(201).json(newPhoto.rows[0]);
    } catch (err) {
        res.status(500).json({ error: "Failed to upload gallery asset." });
    }
});

app.delete('/api/photos/:photoId', async (req, res) => {
    const { photoId } = req.params;
    try {
        await pool.query(`DELETE FROM user_photos WHERE id = $1`, [photoId]);
        res.status(200).json({ success: true, message: "Photo asset wiped successfully." });
    } catch (err) {
        res.status(500).json({ error: "Failed to eliminate targeted photo entry." });
    }
});

app.listen(PORT, () => console.log(`Server executing successfully on port ${PORT}`));