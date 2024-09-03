const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const connection = mongoose.connection;
connection.once('open', () => {
  console.log("MongoDB database connection established successfully");
  createInitialAdminUser();
});

// Define Schemas
const signUpSchema = new mongoose.Schema({
    companyName: String,
    companyAddress: String,
    branchCount: Number,
    contactPerson: String,
    contactEmail: String,
    contactNumber: String,
    timestamp: { type: Date, default: Date.now }
  });

const adminSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    initialPassword: String
  });

const SignUp = mongoose.model('SignUp', signUpSchema);
const Admin = mongoose.model('Admin', adminSchema);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/admin/check-first-login', verifyToken, async (req, res) => {
    try {
      const admin = await Admin.findById(req.user._id);
      const isFirstLogin = admin.password === admin.initialPassword;
      res.json({ isFirstLogin });
    } catch (error) {
      res.status(500).json({ error: 'An error occurred while checking first login status' });
    }
  });

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.post('/api/signup', (req, res) => {
  const newSignUp = new SignUp(req.body);
  newSignUp.save()
    .then(() => res.json('Sign up successful!'))
    .catch(err => res.status(400).json('Error: ' + err));
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin) {
      console.log('Login failed: Admin not found');
      return res.status(400).json({ error: 'Username or password is incorrect' });
    }

    const validPass = await bcrypt.compare(password, admin.password);
    if (!validPass) {
      console.log('Login failed: Invalid password');
      return res.status(400).json({ error: 'Username or password is incorrect' });
    }

    const token = jwt.sign({ _id: admin._id }, process.env.JWT_SECRET);
    res.header('auth-token', token).json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'An error occurred during login' });
  }
});

app.get('/api/admin/signups', verifyToken, (req, res) => {
    SignUp.find()
      .then(signups => res.json(signups))
      .catch(err => res.status(400).json('Error: ' + err));
  });

app.post('/api/admin/change-password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const admin = await Admin.findById(req.user._id);

    const validPass = await bcrypt.compare(currentPassword, admin.password);
    if (!validPass) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    admin.password = hashedPassword;
    await admin.save();

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while changing the password' });
  }
});

// New route to create an admin user
app.post('/api/admin/create', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Check if username or email already exists
    const existingAdmin = await Admin.findOne({ $or: [{ username }, { email }] });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newAdmin = new Admin({
      username,
      password: hashedPassword,
      email
    });

    await newAdmin.save();
    res.status(201).json({ message: 'Admin user created successfully' });
  } catch (error) {
    console.error('Error creating admin user:', error);
    res.status(500).json({ error: 'An error occurred while creating the admin user' });
  }
});

async function createInitialAdminUser() {
    try {
      const adminCount = await Admin.countDocuments();
      if (adminCount === 0) {
        const username = 'admin';
        const password = crypto.randomBytes(8).toString('hex');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
  
        const newAdmin = new Admin({
          username,
          password: hashedPassword,
          email: 'admin@example.com',
          initialPassword: hashedPassword
        });
  
        await newAdmin.save();
        console.log('Initial admin user created:');
        console.log('Username:', username);
        console.log('Password:', password);
        console.log('Please change this password after your first login.');
      }
    } catch (error) {
      console.error('Error creating initial admin user:', error);
    }
  }

const port = process.env.PORT || 5001;
app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});