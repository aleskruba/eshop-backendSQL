require('dotenv').config();
const express = require('express');
const cors = require('cors'); // Add cors middleware
const db = require('./db'); // Import your database connection module
const authRoutes = require('./routes/authRoutes');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const app = express();
const { checkUser } =require('./middleware/authMiddleware');



const corsOptions = {
  origin: 'http://localhost:5173', 
  credentials: true, 
};

app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());
app.use(checkUser);

app.use(
  session({
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60000 } // 1 minute (in milliseconds)
  })
);

app.get('/', async (req, res) => {
  try {
    // Use your db module to execute a query
    const [rows] = await db.query('SELECT * FROM users');
    
    console.log(rows); // Log the retrieved users
    res.json({ users: rows }); // Send the users as a JSON response
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.use('/api', authRoutes);

// ... other routes and configurations ...

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});


