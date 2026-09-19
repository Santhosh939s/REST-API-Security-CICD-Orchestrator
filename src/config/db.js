const mongoose = require('mongoose');

// In-memory mock store fallback for standalone CI/CD test runs (e.g., OWASP ZAP scanning)
const inMemoryStore = {
  active: false,
  users: []
};

const seedInMemoryData = () => {
  inMemoryStore.users = [
    {
      _id: '660000000000000000000001',
      username: 'alice_admin',
      email: 'alice@example.com',
      password: 'password123',
      role: 'admin',
      salary: 145000,
      ssn: '999-12-3456'
    },
    {
      _id: '660000000000000000000002',
      username: 'bob_developer',
      email: 'bob@example.com',
      password: 'password456',
      role: 'user',
      salary: 95000,
      ssn: '888-23-4567'
    }
  ];
  console.log('[+] Seeded in-memory store with sample user records (Alice & Bob).');
};

const connectDB = async () => {
  const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/devsecops_vulnerable_api';
  try {
    mongoose.set('strictQuery', false);
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 2500 });
    console.log(`[+] MongoDB Connected: ${mongoose.connection.host}`);
  } catch (err) {
    console.warn(`[!] MongoDB connection failed (${err.message}). Activating In-Memory Fallback mode for automated CI/CD pipeline scans.`);
    inMemoryStore.active = true;
    seedInMemoryData();
  }
};

module.exports = { connectDB, inMemoryStore, seedInMemoryData };
