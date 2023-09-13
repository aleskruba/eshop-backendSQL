const jwt = require('jsonwebtoken');
const db = require('../db'); 



module.exports.getProducts = async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM products'); // Assuming your table is named 'products'
    res.status(200).json({ products: rows }); // Send the products as a JSON response
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: 'An error occurred while fetching products.' });
  }
};


module.exports.updateProducts = async (req, res, next) => { // Added "next" parameter
  const updatedProducts = req.body.products;
  const basket = req.body.basket; // Basket data from frontend
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next(); // Call the "next" function if an error occurs
      } else {
        try {
          const connection = await db.getConnection();

          for (const updatedProduct of updatedProducts) {
            const productInBasket = basket.find(item => item.id === updatedProduct.id);
            if (productInBasket) {
              const [rows] = await connection.execute('SELECT id FROM products WHERE id = ?', [updatedProduct.id]);
              if (rows.length > 0) {
                await connection.execute('UPDATE products SET amount = ? WHERE id = ?', [updatedProduct.amount, updatedProduct.id]);
              }
            }
          }

          connection.release();
          res.json({ message: 'Product amounts updated successfully.' });
        } catch (error) {
          res.status(500).json({ error: 'An error occurred while updating products.' });
        }
    
      }
    });
  } else {
    res.locals.user = null;
    next(); // Call the "next" function if there's no token
  }
};




module.exports.purchaseProducts = async (req, res, next) => {
  const token = req.cookies.jwt;
  const updatedProducts = req.body.products;
  const basket = req.body.basket;
  const shipment = req.body.shipment;
  const shipmentCost = req.body.shipmentCost;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next(); // Call the "next" function if an error occurs
      } else {
        

        try {
          // Validation of correct price
          const [rows] = await db.execute('SELECT * FROM products');
          const products = rows;

          let totalSum = 0;

          for (const item of basket) {
            const product = products.find((p) => p.id === item.id);

            if (!product) {
              return res.status(400).json({ error: `Product with id ${item.id} not found.` });
            }

            if (item.quantity > product.amount) {
              return res.status(400).json({ error: `Not enough stock for product with id ${item.id}.` });
            }

            totalSum += item.quantity * product.price;
          }

          const shippingCost = shipment ? 10 : 0;
          const finalTotal = totalSum + shippingCost;

          // Update products
          for (const updatedProduct of updatedProducts) {
            const productInBasket = basket.find((item) => item.id === updatedProduct.id);
            if (productInBasket) {
              await db.execute('UPDATE products SET amount = ? WHERE id = ?', [
                updatedProduct.amount,
                updatedProduct.id,
              ]);
            }
          }

          // Find or create the invoice number record
          let invoiceNumber = 2023000; // Default value if no records exist

          const [invoiceRows] = await db.execute('SELECT * FROM invoices ORDER BY currentNumber DESC LIMIT 1');
          const lastInvoiceRecord = invoiceRows[0];

          if (lastInvoiceRecord) {
            invoiceNumber = lastInvoiceRecord.currentNumber + 1;
          }

          // Insert order into the database
          const [orderResult] = await db.execute(
            'INSERT INTO orders (mongoUserId, date, shipment, shipmentCost, basket, invoiceNumber) VALUES (?, ?, ?, ?, ?, ?)',
            [decodedToken.id, new Date(), shipment, shipmentCost, JSON.stringify(basket), invoiceNumber]
          );

          // Get the last inserted order ID
          const orderId = orderResult.insertId;

          // Insert the invoice record
          await db.execute('INSERT INTO invoices (currentNumber, orderNumber) VALUES (?, ?)', [
            invoiceNumber,
            orderId,
          ]);

          res.status(200).json({ message: 'Order saved successfully', orderId, total: finalTotal });
        } catch (err) {
          console.error(err);
          res.status(500).json({ error: 'An error occurred while processing the order.' });
        }
      }
    });
  } else {
    res.locals.user = null;
    next(); // Call the "next" function if there's no token
  }
};
