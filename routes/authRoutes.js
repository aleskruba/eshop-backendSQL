const { Router } = require('express');
const authController = require('../controllers/authController'); // Import the controller functions
const productController = require('../controllers/productController'); 
const messageController = require('../controllers/messageController'); 
const orderController = require('../controllers/orderController'); 
const { checkUser,verifyUserResetPassword,requireAuth } = require('../middleware/authMiddleware');

const router = Router();

router.post('/signup', authController.signup_post);
router.post('/login', authController.login_post);
router.get('/logout', authController.logout_get);
router.post('/fpassword', verifyUserResetPassword,authController.fpassword_post); 
router.post('/verifyOTP',authController.verifyOTP_post) 
router.post('/resetpassword',authController.resetPassword_post)  
router.post('/changepassword',requireAuth,authController.changePassword_post) 
router.get('/getuser',requireAuth,authController.getUser) 
router.put('/updateuser',requireAuth,authController.updateUser_put) 

//products
router.get('/getproducts',productController.getProducts) 
router.put('/updateproducts',requireAuth,productController.updateProducts) 
router.put('/purchaseproducts',requireAuth,productController.purchaseProducts) 

//messages
router.get('/getmessages',messageController.getMessages) 
router.post('/sendmessage',requireAuth,messageController.sendMessage_post) 

//orders
router.get('/getorders',requireAuth,orderController.getOrders) 

router.get('/checkuser', checkUser, (req, res) => {
    if (req.user) {

        res.json({ user: req.user }); // This route should respond with the user data if the user is authenticated
    } 
 
});

module.exports = router;


