const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { HARDCODED_JWT_SECRET } = require('../middleware/auth');
const { inMemoryStore } = require('../config/db');

// Registration endpoint
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role, salary, ssn } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (inMemoryStore.active) {
      const existing = inMemoryStore.users.find(u => u.email === email);
      if (existing) return res.status(409).json({ error: 'User already exists' });
      const newUser = {
        _id: `66000000000000000000000${inMemoryStore.users.length + 1}`,
        username,
        email,
        password,
        role: role || 'user',
        salary: salary || 75000,
        ssn: ssn || '000-00-0000'
      };
      inMemoryStore.users.push(newUser);
      return res.status(201).json({ message: 'User registered successfully', userId: newUser._id });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(409).json({ error: 'User already exists' });

    const user = new User({ username, email, password, role, salary, ssn });
    await user.save();
    return res.status(201).json({ message: 'User registered successfully', userId: user._id });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// =========================================================================================
// [VULNERABILITY: OWASP Top 10 - NoSQL Injection (CWE-943 / A03:2021 - Injection / API8:2023)]
// Description: Direct passing of unvalidated and unsanitized request body objects into
//              the database query selector.
// Attack Payload: { "email": { "$ne": null }, "password": { "$gt": "" } }
// Detection: Flagged by Semgrep SAST rules (express-mongo-nosql-injection) and OWASP ZAP DAST.
// Impact: Complete authentication bypass leading to privilege escalation as the first record.
// =========================================================================================
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    let user;

    if (inMemoryStore.active) {
      // In-memory simulation of NoSQL Injection selector vulnerability
      if (typeof email === 'object' || typeof password === 'object') {
        console.log('[!] NoSQL Injection payload detected and executed against in-memory store!');
        user = inMemoryStore.users[0]; // Bypass authentication: returns first user (alice_admin)
      } else {
        user = inMemoryStore.users.find(u => u.email === email && u.password === password);
      }
    } else {
      // Intentionally vulnerable Mongoose query accepting unvalidated object filters directly
      user = await User.findOne({ email: email, password: password });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Sign JWT using the Hardcoded Secret
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || HARDCODED_JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.json({
      message: 'Authentication successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
