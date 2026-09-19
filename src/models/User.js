const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    default: 'user',
    enum: ['user', 'admin', 'auditor']
  },
  salary: {
    type: Number,
    default: 75000
  },
  ssn: {
    type: String,
    default: '000-00-0000'
  }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
