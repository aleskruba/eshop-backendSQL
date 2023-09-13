const jwt = require('jsonwebtoken');
const db = require('../db'); 


module.exports.sendMessage_post = async (req, res, next) => {
  const data = req.body.data;
  const stars = req.body.stars;
  const token = req.cookies.jwt;

  const today = new Date();

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        try {
          // Create a database connection
          const connection = await db.getConnection();

          // Query the "users" table to retrieve user information
          const [userRows] = await connection.execute(
            'SELECT id, firstName FROM users WHERE id = ?',
            [decodedToken.id]
          );

          // Check if a user was found
          if (userRows.length === 0) {
            res.status(404).json({ error: 'User not found' });
            return;
          }

          const user = userRows[0];

          // Create a new message entry in the "messages" table
          const [messageRows] = await connection.execute(
            'INSERT INTO messages (idUser, username, image, message, stars, date) VALUES (?, ?, ?, ?, ?, ?)',
            [user.id, user.firstName, 'girl2.jpg', data.message, stars, today]
          );

          connection.release(); // Close the database connection

          res.status(200).json({ message: 'Message sent successfully' });
        } catch (err) {
          res.status(400).json({ error: err.message });
        }
      }
    });
  } else {
    res.locals.user = null;
    next(); // Move to the next middleware
  }
};



module.exports.getMessages = async (req, res, next) => {
    try {
      // Create a database connection
      const connection = await db.getConnection();
  
      // Query the "messages" table to retrieve all messages
      const [messageRows] = await connection.execute('SELECT * FROM messages');
  
      connection.release();; // Close the database connection
  
      // Send the messages as JSON response
      res.status(200).json({ comments: messageRows });
    } catch (err) {
      console.log(err);
      res.status(500).json({ error: 'An error occurred while fetching messages.' });
    }

  };