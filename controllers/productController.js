const jwt = require('jsonwebtoken');
const db = require('../db'); 

module.exports.getProducts = async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM products'); 
    res.status(200).json({ products: rows }); 
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
        next(); 
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
    res.status(401).json({ message: 'Unauthorized' });
    next(); 
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

          let invoiceNumber = 2023000; // Default value if no records exist

          const [invoiceRows] = await db.execute('SELECT * FROM invoices ORDER BY currentNumber DESC LIMIT 1');
          const lastInvoiceRecord = invoiceRows[0];

          if (lastInvoiceRecord) {
            invoiceNumber = lastInvoiceRecord.currentNumber + 1;
          }

          const [orderResult] = await db.execute(
            'INSERT INTO orders (mongoUserId, date, shipment, shipmentCost, basket, invoiceNumber) VALUES (?, ?, ?, ?, ?, ?)',
            [decodedToken.id, new Date(), shipment, shipmentCost, JSON.stringify(basket), invoiceNumber]
          );

          const orderId = orderResult.insertId;

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
    res.status(401).json({ message: 'Unauthorized' });
    next(); 
  }
};




module.exports.getProductsAdmin = async (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err) => {
      if (err) {
        next(); 
      } else {
        try {
         
          const [rows] = await pool.query('SELECT * FROM products');

     
          res.status(201).json({ products: rows });
        } catch (err) {
          res.status(400).send(err.message); 
        }
      }
    });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
    next(); 
  }
};

exports.getProductADMIN = async (req, res, next) => {
  const token = req.cookies.jwt;
  const productID = req.query.id; 

  if (token) {
    jwt.verify(token, process.env.KEY, async (err) => {
      if (err) {
        next(); 
      } else {
        try {
         
          const [rows] = await db.query('SELECT * FROM products WHERE id = ?', [productID]);

          if (rows.length === 1) {
            const product = rows[0];
            res.status(201).json({ product });
          } else {
            res.status(404).json({ error: 'Product not found' });
          }
        } catch (err) {
          res.status(400).send(err.message); 
        }
      }
    });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
    next(); 
  }
};



exports.updateProductADMIN_put = async (req, res, next) => {
  const data = req.body.data;
  const token = req.cookies.jwt;
  const productID = req.body.productID;


  if (token) {
    jwt.verify(token, process.env.KEY, async (err) => {
      if (err) {
        next(); 
      } else {
        try {
          
          const [rows] = await db.query('UPDATE products SET ? WHERE id = ?', [data, productID]);

          if (rows.affectedRows === 1) {
            res.status(200).json({ message: 'Product updated successfully' });
          } else {
            res.status(404).json({ error: 'Product not found' });
          }
        } catch (err) {
          res.status(400).json({ error: err.message });
        }
      }
    });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
    next(); 
  }
};



exports.savenewproductADMIN_post = async (req, res, next) => {
  const data = req.body.data;
  const token = req.cookies.jwt; 

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        next(); 
      } else {
        try {

          const price = parseInt(data.price, 10);
          const amount = parseInt(data.amount, 10);

          const query = 'INSERT INTO products (name, price, amount, image, title, description, discount) VALUES (?, ?, ?, ?, ?, ?, ?)';
          const values = [data.name, price, amount, data.image, data.title, data.description, data.discount];

          const [result] = await db.query(query, values);

          if (result && result.affectedRows === 1) {
            res.status(200).json({ message: 'Product saved successfully' });
          } else {
            res.status(500).json({ error: 'Product could not be saved' });
          }
        } catch (err) {
          res.status(400).json({ error: 'could not save the data' });
        }
      }
    });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
    next(); 
  }
};
