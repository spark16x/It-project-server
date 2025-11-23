import express from "express";
import axios from "axios";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import { pool } from "./db.js";

dotenv.config();

const app = express();
app.use(cors({ origin: "https://edudel-lite.vercel.app", credentials: true }));
app.use(cookieParser());
app.use(express.json());

// Step 1: Redirect user to Google OAuth
app.get("/auth/google", (req, res) => {
  const url =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: process.env.GOOGLE_REDIRECT_URL,
      response_type: "code",
      scope: "openid email profile",
      prompt: "select_account"
    });
  
  res.redirect(url);
});

// Step 2: Google redirects back with "code"
app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code;
  
  try {
    // Exchange code → tokens
    const tokenRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URL,
        grant_type: "authorization_code"
      }, { headers: { "Content-Type": "application/json" } }
    );
    
    const { access_token, id_token } = tokenRes.data;
    
    // Fetch user info
    const userRes = await axios.get(
      "https://www.googleapis.com/oauth2/v3/userinfo", { headers: { Authorization: `Bearer ${access_token}` } }
    );
    
    const profile = userRes.data;
    
    // Check if user exists in DB
    let result = await pool.query(
      "SELECT * FROM users WHERE google_id = $1",
      [profile.sub]
    );
    
    let user;
    if (result.rows.length === 0) {
      // New user -> insert
      const insert = await pool.query(
        "INSERT INTO users (google_id, name, email, picture) VALUES ($1,$2,$3,$4) RETURNING *",
        [profile.sub, profile.name, profile.email, profile.picture]
      );
      user = insert.rows[0];
    } else {
      user = result.rows[0];
    }
    
    // Create JWT Token
    const token = { id: user.id, email: user.email, name: user.name, picture: user.picture };
    
    res.redirect(`https://edudel-lite.vercel.app/auth/success?token=${token}`);
  } catch (err) {
    console.log(err.response?.data || err);
    res.status(500).json({ error: "OAuth failed" });
  }
});




// Manual Signup Route (Name + Email + Password)
app.post("/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Validate
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    
    // Check if user exists
    const checkUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    
    if (checkUser.rows.length > 0) {
      return res.status(409).json({ error: "User already exists" });
    }
    
    // Insert user
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1,$2,$3) RETURNING *",
      [name, email, password] // You can hash later bro
    );
    
    const user = newUser.rows[0];
    
    // Create JWT token
    const token = jwt.sign({ id: user.id, email: user.email },
      process.env.JWT_SECRET, { expiresIn: "7d" }
    );
    
    // Send response with token
    res.status(201).json({
      message: "Signup completed",
      token,
      user
    });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1️⃣ Find user by email
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];

    // 2️⃣ Direct password match (no bcrypt)
    if (user.password !== password) {
      return res.status(400).json({ error: "Invalid password" });
    }

    // 3️⃣ Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // 4️⃣ Send user + token
    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        picture: user.picture,
      },
    });

  } catch (err) {
    console.log("Login Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected route example
app.get("/me", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "No token" });
  
  const user = jwt.verify(token, process.env.JWT_SECRET);
  res.json(user);
});

app.listen(5000, () =>
  console.log("🔥 Server running on http://localhost:5000")
);