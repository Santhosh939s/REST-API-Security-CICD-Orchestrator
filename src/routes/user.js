const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { verifyToken } = require('../middleware/auth');
const { inMemoryStore } = require('../config/db');

// Directory listing (Public / Authenticated test fixture)
router.get('/', verifyToken, async (req, res) => {
  try {
    if (inMemoryStore.active) {
      const sanitized = inMemoryStore.users.map(({ password, ...u }) => u);
      return res.json({ count: sanitized.length, users: sanitized });
    }
    const users = await User.find().select('-password');
    return res.json({ count: users.length, users });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// =========================================================================================
// [VULNERABILITY: OWASP Top 10 - Broken Object Level Authorization / BOLA (CWE-639 / API1:2023)]
// Description: The endpoint retrieves and returns full sensitive user profiles (including SSN
//              and salary) based solely on the URL :id parameter. It does NOT verify whether
//              the authenticated token owner (req.user.id) matches req.params.id or possesses admin rights.
// Attack Vector: An authenticated standard user replaces their own ID with another user's ID
//                (e.g., GET /api/users/660000000000000000000001).
// Impact: Critical confidentiality breach; horizontal/vertical privilege disclosure.
// =========================================================================================
router.get('/:id', verifyToken, async (req, res) => {
  try {
    const targetId = req.params.id;

    if (inMemoryStore.active) {
      const targetUser = inMemoryStore.users.find(u => u._id === targetId);
      if (!targetUser) {
        return res.status(404).json({ error: 'User not found' });
      }
      const { password, ...userRecord } = targetUser;
      return res.json({
        message: 'User profile retrieved successfully',
        profile: userRecord,
        warning: '[BOLA Expose] Retrieved without verifying requester ownership!'
      });
    }

    const user = await User.findById(targetId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({
      message: 'User profile retrieved successfully',
      profile: user,
      warning: '[BOLA Expose] Retrieved without verifying requester ownership!'
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// =========================================================================================
// [VULNERABILITY: OWASP Top 10 - BOLA / IDOR on Resource Modification (CWE-639 / API1:2023)]
// Description: Allows any authenticated user to tamper with arbitrary user profiles (roles, salary).
// =========================================================================================
router.put('/:id', verifyToken, async (req, res) => {
  try {
    const targetId = req.params.id;
    const updates = req.body;

    if (inMemoryStore.active) {
      const idx = inMemoryStore.users.findIndex(u => u._id === targetId);
      if (idx === -1) return res.status(404).json({ error: 'User not found' });

      inMemoryStore.users[idx] = { ...inMemoryStore.users[idx], ...updates };
      const { password, ...updatedUser } = inMemoryStore.users[idx];
      return res.json({ message: 'Profile updated', profile: updatedUser });
    }

    const updatedUser = await User.findByIdAndUpdate(targetId, updates, { new: true }).select('-password');
    if (!updatedUser) return res.status(404).json({ error: 'User not found' });

    return res.json({ message: 'Profile updated', profile: updatedUser });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
