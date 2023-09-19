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
         next();
      } else {
        try {
          const connection = await db.getConnection();

          const [userRows] = await connection.execute(
            'SELECT id, firstName FROM users WHERE id = ?',
            [decodedToken.id]
          );

          if (userRows.length === 0) {
            res.status(404).json({ error: 'User not found' });
            return;
          }

          const user = userRows[0];

          const [messageRows] = await connection.execute(
            'INSERT INTO messages (idUser, username, image, message, stars, date) VALUES (?, ?, ?, ?, ?, ?)',
            [user.id, user.firstName, 'girl2.jpg', data.message, stars, today]
          );

          connection.release(); 

          res.status(200).json({ message: 'Message sent successfully' });
        } catch (err) {
          res.status(400).json({ error: err.message });
        }
      }
    });
  } else {
    res.status(401).send({message:'Unathorized'});
    next(); 
  }
};



module.exports.getMessages = async (req, res, next) => {
    try {
   
      const connection = await db.getConnection();
  
      const [messageRows] = await connection.execute('SELECT * FROM messages');
  
      connection.release();; 
  
      res.status(200).json({ comments: messageRows });
    } catch (err) {
      console.log(err);
      res.status(500).json({ error: 'An error occurred while fetching messages.' });
    }

  };