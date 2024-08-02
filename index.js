require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const User = require('./models/User');
const ToDo = require('./models/ToDo');

// Initialize Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const app = express();
app.use(express.json());

// Connect to MongoDB

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB', err));


// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access Denied');
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

// Register new user
app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;

  // Supabase registration logic
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return res.status(400).send(error.message);

  // Hash password and save user to MongoDB
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = new User({ email, password: hashedPassword, name });
  try {
    await user.save();
    res.send('User registered');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).send('Email or password is wrong');

  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).send('Invalid password');

  const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.header('Authorization', token).send({ token });
});

// CRUD operations for ToDo
app.post('/todos', authenticateToken, async (req, res) => {
  const { task } = req.body;
  const todo = new ToDo({
    userId: req.user._id,
    task,
  });
  try {
    await todo.save();
    res.send(todo);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get('/todos', authenticateToken, async (req, res) => {
  try {
    const todos = await ToDo.find({ userId: req.user._id });
    res.send(todos);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.put('/todos/:id', authenticateToken, async (req, res) => {
  try {
    const todo = await ToDo.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      req.body,
      { new: true }
    );
    if (!todo) return res.status(404).send('ToDo item not found');
    res.send(todo);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.delete('/todos/:id', authenticateToken, async (req, res) => {
  try {
    const todo = await ToDo.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id,
    });
    if (!todo) return res.status(404).send('ToDo item not found');
    res.send('ToDo item deleted');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Session management (optional)
app.get('/sessions', authenticateToken, async (req, res) => {
  // Add logic to retrieve user sessions
  res.send('Sessions endpoint');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
