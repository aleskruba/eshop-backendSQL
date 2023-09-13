const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const db = require('../db'); 
const nodemailer = require('nodemailer');

const createToken = (id) => {
  return jwt.sign({ id }, process.env.KEY, {
    expiresIn: '10d'
  });
};

const createRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.KEY, {
    expiresIn: '360d'
  });
};

module.exports.refresh_token_post = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token not found' });
  }
  try {
    const decoded = jwt.verify(refreshToken, process.env.KEY);
    const accessToken = createToken(decoded.id);
    res.cookie('jwt', accessToken, { httpOnly: true, maxAge: 5 * 24 * 60* 60 * 1000 });
    res.status(200).json({ accessToken });
  } catch (err) {
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};


module.exports.signup_post = async (req, res) => {
  const { data } = req.body;
  const email = data.email;
  const password = data.password;

  try {
    const [existingUserRows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (existingUserRows.length > 0) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    const insertUserQuery = 'INSERT INTO users (email, password) VALUES (?, ?)';
    const [insertUserResult] = await db.query(insertUserQuery, [email, hashedPassword]);

    if (insertUserResult.affectedRows !== 1) {
      throw new Error('User creation failed');
    }

    const userId = insertUserResult.insertId;

    /* 
      The rest of your code for token creation and response can be added here.
    */

    res.status(201).json({ user: userId });
  } catch (error) {
    console.error('Error during sign-up:', error);
    res.status(500).json({ error: 'An error occurred during sign-up. Please try again later.' });
  }
};


module.exports.login_post = async (req, res) => {
  const { data } = req.body;

  try {
    const connection = await db.getConnection();

    try {
      // Fetch user by email
      const [userRows] = await connection.execute('SELECT * FROM users WHERE email = ?', [data.email]);
      
      if (userRows.length === 0) {
        return res.status(400).json({ error: 'User not found' });
      }

      const user = userRows[0];

      // Check password
      const passwordMatch = await bcrypt.compare(data.password, user.password);
      
      if (!passwordMatch) {
        return res.status(400).json({ error: 'Wrong email or password' });
      }

      const accessToken = createToken(user.id); // Assuming 'id' is the primary key column name
      const refreshToken = createRefreshToken(user.id); // Assuming 'id' is the primary key column name

      res.cookie('jwt', accessToken, { httpOnly: true, maxAge: 5 * 24 * 60 * 60 * 1000 });
      res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
      res.status(200).json({ user: user._id , userData:user});
    } catch (error) {
      console.log('Error during login:', error);
      res.status(500).json({ error: 'Internal server error' });
    } 
  } catch (err) {
    console.log('Error acquiring database connection:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports.logout_get = (req, res) => {
  try {
    res.cookie('jwt', '', { maxAge: 1, httpOnly: true });
    res.status(200).json({ message: 'Logout successful' });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'An error occurred during logout.' });
  }
};

module.exports.fpassword_post = async (req, res) => {
  const { email } = req.body;
    
  try {
   

    // Access the OTP from the session
    const otp = req.session.otp.value;
  

    // Your other code to send the OTP via email goes here...
    let transporter = nodemailer.createTransport({
      host: 'smtp.centrum.cz',
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.EMAILUSER, // your email address
        pass: process.env.EMAILPASSWORD, // your email password
      },
    });

    let mailOptions = {
      from: process.env.EMAILUSER, // sender address
      to: email, // list of receivers
      subject: 'VÝVOJÁŘKÝ TEST ZAPOMENUTÉHO HESLA', // Subject line
      text: ` ${email}, NOVÝ KÓD ${otp}`, // plain text body
      html: `<b>${otp}</b>`, // html body
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        // Handle the error here if needed
        res.status(500).json({ error: 'Email sending failed' });
      } else {
        // Success response
        res.status(200).json({ message: 'OTP sent successfully!' });
      }
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Internal server error' });
  }   
};

module.exports.verifyOTP_post = async (req, res) => {
  try {
    const { code } = req.body;
    const storedOTP = req.session.otp;

    if (storedOTP.value === code && Date.now() < storedOTP.expires) {
      // OTP is valid and not expired
      req.session.isAuthenticated = true;
      res.status(200).json({ message: 'OTP verified successfully!' });
    } else {
      // OTP is invalid or expired
      res.status(401).json({ error: 'Invalid OTP or session expired.' });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'Internal server error' });
  }
};



module.exports.resetPassword_post = async (req, res) => {
  const { password, email } = req.body;
  

  try {
    if (password.length < 6) {
      throw new Error('Password must be at least 6 characters');
    }

    const [userRows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (userRows.length === 0) {
      throw new Error(`User not found for email: ${email}`);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [updateRows] = await db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);

    if (updateRows.affectedRows === 0) {
      throw new Error('Password update failed');
    }

    res.status(200).json({ user: userRows[0].id }); // Adjust the property according to your database schema

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
};




module.exports.getUser = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        try {
          const connection = await db.getConnection();

          const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [decodedToken.id]);
          const user = rows[0];

       
          if (user) {
            res.locals.user = user;
            res.status(201).json({ user: user });
            next();
          } else {
            res.locals.user = null;
            next();
          }
        } catch (err) {
          res.status(400).send(err.message);
        }
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};


module.exports.changePassword_post = async (req, res, next) => {
  const { oldPassword, newPassword } = req.body;
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        try {
          const connection = await db.getConnection();

          const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [decodedToken.id]);
          const user = rows[0];

          if (!user) {
            connection.release();
            res.locals.user = null;
            next();
            return;
          }

          const passwordMatch = await bcrypt.compare(oldPassword, user.password);
          if (!passwordMatch) {
            connection.release();
            throw new Error('incorrect old password');
          }

          if (newPassword.length < 6) {
            connection.release();
            throw new Error('incorrect new password');
          }

          const hashedPassword = await bcrypt.hash(newPassword, 10);

          await connection.execute('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, decodedToken.id]);
          connection.release();

          res.status(201).json({ user: 'password changed' });
          return;
        } catch (err) {
          res.status(400).send(err.message);
          return;
        }
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};


module.exports.updateUser_put = async (req, res, next) => {
  const data = req.body.data;
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        try {
          const connection = await db.getConnection();

          const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [decodedToken.id]);
          const user = rows[0];

          if (!user) {
            connection.release();
            res.locals.user = null;
            next();
            return;
          }

          const updateFields = Object.keys(data).map(key => `${key} = ?`).join(', ');
          const updateValues = Object.values(data);
          updateValues.push(decodedToken.id);

          await connection.execute('UPDATE users SET ' + updateFields + ' WHERE id = ?', updateValues);
          connection.release();

          res.status(200).json({ message: 'updated successfully' });
        } catch (err) {
          res.status(400).json({ error: err.message });
        }
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};