const jwt = require('jsonwebtoken');
const db = require('../db'); 


module.exports.getOrders = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        next();
      } else {
        try {
          const [rows, fields] = await db.query('SELECT * FROM orders'); // Execute a SQL query to retrieve orders
          res.status(200).json({ orders: rows }); // Send the orders as a JSON response
        } catch (dbError) {
          console.error(dbError);
          res.status(500).json({ error: 'An error occurred while fetching orders.' });
        }
      }
    });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
    next();
  }
};