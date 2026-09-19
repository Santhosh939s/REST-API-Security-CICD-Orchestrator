require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { connectDB, inMemoryStore, seedInMemoryData } = require('./src/config/db');

const authRoutes = require('./src/routes/auth');
const userRoutes = require('./src/routes/user');

const app = express();
const PORT = process.env.PORT || 5000;

// Core Middleware
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

// Initialize Database connection (graceful fallback if MongoDB is not running)
connectDB();

// Liveness & Readiness probe for CI/CD runners and OWASP ZAP baseline scans
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    service: 'REST API Security CI/CD Orchestrator',
    inMemoryFallback: !!inMemoryStore.active
  });
});

// Seed endpoint for quick environment re-initialization during DAST test suites
app.post('/api/seed', (req, res) => {
  seedInMemoryData();
  res.status(200).json({ message: 'Environment re-seeded successfully' });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.url}` });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Error]:', err.stack);
  res.status(500).json({ error: 'Internal Server Error', details: err.message });
});

// Export app for integration tests or start server if invoked directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`========================================================`);
    console.log(`[🚀] Security Orchestrator API listening on port ${PORT}`);
    console.log(`[🎯] Health endpoint: http://localhost:${PORT}/health`);
    console.log(`[⚠️] INTENTIONALLY VULNERABLE LAB ENVIRONMENT`);
    console.log(`========================================================`);
  });
}

module.exports = app;
