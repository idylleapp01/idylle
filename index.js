const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get('/', (req, res) => {
  res.send('Welcome to the Idylle Dating App API!');
});

// SIGNUP ROUTE (Now saves a hashed secret answer for recovery)
app.post('/api/signup', async (req, res) => {
  const { name, email, username, phone_number, password, birthday, gender, bio, secretAnswer } = req.body;
  if (!name || !email || !password || !username || !secretAnswer) {
    return res.status(400).json({ error: "Name, email, username, password, and security answer are required." });
  }
  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "An account with this email or username already exists." });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const answerHash = await bcrypt.hash(secretAnswer.toLowerCase().trim(), salt);
    
    const newUser = await pool.query(
      `INSERT INTO users (name, email, username, phone_number, password_hash, birthday, gender, bio, secret_answer) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, name, email`,
      [name, email, username, phone_number, passwordHash, birthday, gender, bio, answerHash]
    );
    res.status(201).json({ message: "User registered successfully!", user: newUser.rows[0] });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error." }); }
});

// LOGIN ROUTE
app.post('/api/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: "Login identifier and password are required." });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $1 OR phone_number = $1', [identifier]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid credentials." });
    
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials." });
    
    res.status(200).json({ message: "Login successful!", user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error." }); }
});

// PASSWORD RESET ROUTE (Verifies identifier + secret answer, then overwrites password)
app.post('/api/reset-password', async (req, res) => {
  const { identifier, secretAnswer, newPassword } = req.body;
  if (!identifier || !secretAnswer || !newPassword) {
    return res.status(400).json({ error: "All fields are required to reset your password." });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $1 OR phone_number = $1', [identifier]);
    if (result.rows.length === 0) return res.status(400).json({ error: "User account not found." });

    const user = result.rows[0];
    
    // Verify security answer match
    const isAnswerCorrect = await bcrypt.compare(secretAnswer.toLowerCase().trim(), user.secret_answer);
    if (!isAnswerCorrect) return res.status(400).json({ error: "Incorrect security answer verification failed." });

    // Hash and update to the new password
    const salt = await bcrypt.genSalt(10);
    const newPasswordHash = await bcrypt.hash(newPassword, salt);

    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, user.id]);

    res.status(200).json({ message: "Password updated successfully! You can now log in." });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error during recovery." }); }
});

// DISCOVER ROUTE
app.get('/api/users/discover', async (req, res) => {
  const currentUserId = req.query.userId;
  try {
    let queryText = 'SELECT id, name, birthday, gender, bio, profile_pic_url FROM users';
    let queryParams = [];
    if (currentUserId) {
      queryText += ` WHERE id != $1 AND id NOT IN (SELECT liked_id FROM likes WHERE liker_id = $1)`;
      queryParams.push(currentUserId);
    }
    queryText += ' LIMIT 20';
    const result = await pool.query(queryText, queryParams);
    res.status(200).json(result.rows);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error." }); }
});

// LIKE ROUTE
app.post('/api/like', async (req, res) => {
  const { likerId, likedId } = req.body;
  if (!likerId || !likedId) return res.status(400).json({ error: "Required fields missing." });
  try {
    await pool.query('INSERT INTO likes (liker_id, liked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [likerId, likedId]);
    const mutualLike = await pool.query('SELECT * FROM likes WHERE liker_id = $1 AND liked_id = $2', [likedId, likerId]);
    res.status(200).json({ message: "Like recorded!", match: mutualLike.rows.length > 0 });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error." }); }
});

// SEND MESSAGE ROUTE
app.post('/api/messages', async (req, res) => {
  const { senderId, receiverId, messageText } = req.body;
  if (!senderId || !receiverId || !messageText) return res.status(400).json({ error: "Required fields missing." });
  try {
    const newMessage = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, message_text) VALUES ($1, $2, $3) RETURNING *`,
      [senderId, receiverId, messageText]
    );
    res.status(201).json(newMessage.rows[0]);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error." }); }
});

// GET CONVERSATION ROUTE
app.get('/api/messages', async (req, res) => {
  const { userOne, userTwo } = req.query;
  if (!userOne || !userTwo) return res.status(400).json({ error: "User IDs required." });
  try {
    const conversation = await pool.query(
      `SELECT * FROM messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1) ORDER BY created_at ASC`,
      [userOne, userTwo]
    );
    res.status(200).json(conversation.rows);
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error." }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Idylle server running on port ${PORT}`));