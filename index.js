const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(express.json());

// Connect to Neon Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Base Route
app.get('/', (req, res) => {
  res.send('Welcome to the Idylle Dating App API!');
});

// SIGNUP ROUTE: Registers a new user
app.post('/api/signup', async (req, res) => {
  const { name, email, password, birthday, gender, bio } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are required." });
  }

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "An account with this email already exists." });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      `INSERT INTO users (name, email, password_hash, birthday, gender, bio) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, name, email, created_at`,
      [name, email, passwordHash, birthday, gender, bio]
    );

    res.status(201).json({
      message: "User registered successfully!",
      user: newUser.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error during registration." });
  }
});

// LOGIN ROUTE: Verifies user credentials
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  // 1. Basic validation
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    // 2. Look up the user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    const user = result.rows[0];

    // 3. Compare the incoming password with the database hash
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password." });
    }

    // 4. Login successful! (Send back user info excluding password)
    res.status(200).json({
      message: "Login successful!",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        birthday: user.birthday,
        gender: user.gender,
        bio: user.bio
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error during login." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Idylle server running on port ${PORT}`));