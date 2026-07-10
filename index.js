const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(express.json());

// Connect to Neon Database using the environment variable
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for Neon cloud hosting
});

// Base Route
app.get('/', (req, res) => {
  res.send('Welcome to the Idylle Dating App API!');
});

// Test Database Route
app.get('/db-test', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ message: "Connected to Neon successfully!", time: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database connection error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Idylle server running on port ${PORT}`));