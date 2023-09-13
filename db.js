const mysql = require('mysql2');

const HOST = process.env.HOST;
const PORT = process.env.PORT;
const USER = process.env.USER;
const PASSWORD = process.env.PASSWORD;
const DATABASE = process.env.DATABASE;

const pool = mysql.createPool({
  host: HOST,
  port: PORT,
  user: USER,
  password: PASSWORD,
  database: DATABASE,
  connectionLimit: 10,
});

module.exports = pool.promise();



