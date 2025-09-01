const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/UserModel');
const {
  getAllUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  updateUserRole
} = require('../controllers/userController');
const { protect, authorize } = require('../middleware/authMiddleware');


router.get('/', async (req, res) => {
  try {
  
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


router.post('/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        status: 'fail', 
        message: 'User already exists with this email' 
      });
    }
    
    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'customer'
    });
    
    await newUser.save();
    
    res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

router.route('/')
  .get(protect, authorize('admin'), getAllUsers)
  .post(protect, authorize('admin'), createUser);

router.route('/:id')
  .get(protect, authorize('admin'), getUser)
  .put(protect, authorize('admin'), updateUser)
  .delete(protect, authorize('admin'), deleteUser);

router.put('/:id/role', protect, authorize('admin'), updateUserRole);


router.get('/users', async (req, res) => {
  try {
    const users = await User.find(); 
    console.log('Fetched users:', users); 
    res.json(users); 
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: err.message });
  }
});
module.exports = router;