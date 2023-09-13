const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const db = require('../db'); 
const nodemailer = require('nodemailer');

module.exports.getOrders = async (req, res, next) => {

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next(); // Move to the next middleware in case of an error
      } else {

    try {
      const [rows, fields] = await db.query('SELECT * FROM orders'); // Execute a SQL query to retrieve orders
      res.status(200).json({ orders: rows }); // Send the orders as a JSON response
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'An error occurred while fetching orders.' });
    }

  }
})}
  };
 
  
  
  