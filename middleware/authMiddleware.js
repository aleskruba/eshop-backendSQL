const jwt = require('jsonwebtoken');
const db = require('../db'); 
const otpGenerator = require('otp-generator');

const requireAuth = async (req, res, next) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, (err, decodedToken) => {
      if (err) {
        console.log(err.message);
        return res.status(401).json({ message: 'Unauthorized' });
      } else {
        // Token is valid, continue to the next middleware or route handler
        req.user = decodedToken; // Save the user data from the token in the request object
        next();
      }
    });
  } else {
    return res.status(401).json({ message: 'Unauthorized' });
  }
};


const checkUser = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    try {
      const decodedToken = await jwt.verify(token, process.env.KEY);
      req.user = decodedToken; // Save the user data from the token in the request object

      try {
        const [userRows] = await db.execute('SELECT * FROM users WHERE id = ?', [
          req.user.id,
        ]);

        if (userRows.length > 0) {
          // The 'userRows' variable now contains the user data from the database
          req.user = userRows[0];
        } else {
          // Handle the scenario when the user is not found (optional)
          console.log('User not found in the database');
          // Optionally, you can set req.user to null or perform any other action here.
        }

        next();
      } catch (error) {
        console.log('Error fetching user from database:', error);
        req.user = null;
        next();
      }
    } catch (err) {
      // Handle any error that occurs during verification
      console.log('Error verifying token:', err);
      req.user = null;
      next();
    }
  } else {
    req.user = null;
    next();
  }
};




async function generateOTP(length) {
  try {
    const otp = await otpGenerator.generate(length, {
      upperCaseAlphabets: false,
      specialChars: false,
    });
    return otp;
  } catch (error) {
    console.error('Error generating OTP:', error);
    throw error;
  }
}



async function verifyUserResetPassword(req, res, next) {
  try {
    const { email } = req.method === "GET" ? req.query : req.body;

    // Generate OTP and set it in req.app.locals
    const otp = await generateOTP(6);

    req.app.locals.OTP = otp;
    req.session.otp = { value: otp, expires: Date.now() + 60000 }; // 1 minute

    // Check the user existence
    const [userRows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (userRows.length === 0) {
      return res.status(404).json({ error: "Can't find User!" });
    }

    // If the user exists and OTP is generated, proceed to the next middleware
    res.status(201).json({ status: "OK" });
    next();
  } catch (error) {
    console.error('Error in verifyUserResetPassword:', error);
    return res.status(404).json({ error: "Authentication Error" });
  }
}




module.exports = {checkUser,verifyUserResetPassword,generateOTP,requireAuth};
