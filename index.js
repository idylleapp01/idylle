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

  // Basic validation
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are required." });
  }

  try {
    // 1. Check if the user already exists
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "An account with this email already exists." });
    }

    // 2. Hash the password securely
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // 3. Insert the new user into the database
    const newUser = await pool.query(
      `INSERT INTO users (name, email, password_hash, birthday, gender, bio) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, name, email, created_at`,
      [name, email, passwordHash, birthday, gender, bio]
    );

    // 4. Respond with the new user's details (excluding password)
    res.status(201).json({
      message: "User registered successfully!",
      user: newUser.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error during registration." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Idylle server running on port ${PORT}`));