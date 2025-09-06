require('dotenv').config();
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');
const bcrypt = require('bcrypt');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);


// Create upload directories if not exist
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');
if (!fs.existsSync('./uploads/pdfs')) fs.mkdirSync('./uploads/pdfs');
if (!fs.existsSync('./uploads/thumbnails')) fs.mkdirSync('./uploads/thumbnails');

// Multer storage config
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (file.fieldname === 'pdf') cb(null, './uploads/pdfs');
    else if (file.fieldname === 'thumbnail') cb(null, './uploads/thumbnails');
    else cb(null, './uploads');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Add subscription check middleware
const checkSubscription = (req, res, next) => {
  if (!req.user.is_subscribed && req.user.books_read >= 5) {
    return res.redirect('/subscribe');
  }
  next();
};



const express = require('express');
const path = require('path');
const db = require('./db');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const session = require('express-session');
const cookieParser = require('cookie-parser');


app.use(cookieParser());
app.use(session({
  secret: 'some_strong_secret',
  resave: false,
  saveUninitialized: false,
  // cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Promisify SQLite methods
const dbGet = promisify(db.get).bind(db);
const dbRun = promisify(db.run).bind(db);


const PORT = 3000;

function isLoggedIn(req, res, next) {
  if (req.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

function isAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Access denied. Admins only.');
  }
}

// Set req.user from session for every request
app.use((req, res, next) => {
  if (req.session && req.session.user) {
    req.user = req.session.user;
  } else {
    req.user = null;
  }
  res.locals.user = req.user; 
  next();
});





app.set('view engine', 'ejs');
app.use(expressLayouts); 
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));



// Home redirect
// app.get('/', (req, res) => res.redirect('/login'));
// app.get('/', (req, res) => {
//   if (req.session && req.session.user) {
//     res.redirect('/dashboard');
//   } else {
//     res.redirect('/login');
//   }
// });


app.get('/', (req, res) => {
  // Step 1: Check login
  if (req.session && req.session.user) {
    return res.redirect('/dashboard'); // original behavior preserved
  }

  // Step 2: Load data for guests
  db.all('SELECT * FROM sections', (err, sections) => {
    if (err) return res.status(500).send('Database error');

    // Load books for each section
    const sectionPromises = sections.map(section => {
      return new Promise((resolve, reject) => {
        db.all('SELECT * FROM books WHERE section_id = ?', [section.id], (err, books) => {
          if (err) return reject(err);
          section.books = books;
          resolve();
        });
      });
    });

    Promise.all(sectionPromises)
      .then(() => {
        res.render('index', {
          sections,
          user: null // explicitly no session user
        });
      })
      .catch(() => res.status(500).send('Database error'));
  });
});


// Login Page
app.get('/login', (req, res) => res.render('login', { error: null}));

// Register Page
app.get('/register', (req, res) => res.render('register', { error: null }));

// Books Page
app.get('/books', (req, res) => {
  db.all('SELECT * FROM books', (err, books) => {
    res.render('books', { books });
  });
});
// admin_dashboard
app.get('/admin', isLoggedIn, isAdmin, (req, res) => {
  const bookQuery = `
    SELECT books.*, sections.name AS section_name
    FROM books
    JOIN sections ON books.section_id = sections.id
  `;

  db.all(bookQuery, (err, books) => {
    if (err) return res.status(500).send('Database error');
    
    db.all('SELECT * FROM users', (err2, users) => {
      if (err2) return res.status(500).send('Database error');
      
      res.render('admin_dashboard', { books, users });
    });
  });
});


// Add Section Page
app.get('/add-section', isLoggedIn, isAdmin, (req, res) => {
  res.render('add_section', { error: null });
});

// Handle Add Section
app.post('/add-section', isLoggedIn, isAdmin, (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return res.render('add_section', { error: 'Section name is required.' });
  }

  db.run(
    'INSERT INTO sections (name, description) VALUES (?, ?)',
    [name, description],
    function (err) {
      if (err) {
        res.render('add_section', { error: 'Error adding section. It may already exist.' });
      } else {
        res.redirect('/add-book'); // or wherever makes sense in your flow
      }
    }
  );
});



// GET: Show add book form with all available sections
app.get('/add-book', isLoggedIn, isAdmin, (req, res) => {
  db.all('SELECT id, name FROM sections', (err, sections) => {
    if (err) {
      res.render('add_book', { error: 'Failed to load sections.', sections: [] });
    } else {
      res.render('add_book', { error: null, sections });
    }
  });
});

// POST: Handle book submission
app.post(
  '/add-book',
  isLoggedIn,
  isAdmin,
  upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'thumbnail', maxCount: 1 }
  ]),
  (req, res) => {
    const { title, author, section_id } = req.body;
    const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : null;
    const thumbnail = req.files['thumbnail'] ? req.files['thumbnail'][0].filename : null;

    // Validate inputs
    if (!title || !author || !section_id || !pdf || !thumbnail) {
      db.all('SELECT id, name FROM sections', (err, sections) => {
        return res.render('add_book', {
          error: 'All fields are required, including section.',
          sections: sections || []
        });
      });
      return;
    }

    // Save book to DB
    db.run(
      'INSERT INTO books (title, author, pdf, thumbnail, section_id) VALUES (?, ?, ?, ?, ?)',
      [title, author, pdf, thumbnail, section_id],
      function (err) {
        if (err) {
          db.all('SELECT id, name FROM sections', (error, sections) => {
            return res.render('add_book', {
              error: 'Error saving book. Try again.',
              sections: sections || []
            });
          });
        } else {
          res.redirect('/admin'); // or wherever you want
        }
      }
    );
  }
);


// Edit BOOK
app.get('/edit-book/:id', isLoggedIn, isAdmin, (req, res) => {
  const bookId = req.params.id;

  db.get('SELECT * FROM books WHERE id = ?', [bookId], (err, book) => {
    if (err || !book) return res.status(404).send('Book not found');

    db.all('SELECT id, name FROM sections', (secErr, sections) => {
      if (secErr) return res.status(500).send('Error loading sections');

      res.render('edit_book', { book, sections, error: null });
    });
  });
});

app.post('/edit-book/:id',
  isLoggedIn,
  isAdmin,
  upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'thumbnail', maxCount: 1 }
  ]),
  (req, res) => {
    const { title, author } = req.body;
    const id = req.params.id;

    db.get('SELECT * FROM books WHERE id = ?', [id], (err, book) => {
      if (!book) return res.status(404).send('Book not found');

      const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : book.pdf;
      const thumbnail = req.files['thumbnail'] ? req.files['thumbnail'][0].filename : book.thumbnail;

      db.run(
        'UPDATE books SET title = ?, author = ?, pdf = ?, thumbnail = ? WHERE id = ?',
        [title, author, pdf, thumbnail, id],
        function (err) {
          if (err) {
            res.render('edit_book', { book, error: 'Error updating book.' });
          } else {
            res.redirect('/admin');
          }
        }
      );
    });
  }
);



// Users Page (for admin)
app.get('/users', (req, res) => {
  db.all('SELECT * FROM users', (err, users) => {
    res.render('users', { users });
  });
});

// Handle Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Something went wrong. Try again.' });
    }

    if (!user) {
      return res.render('login', { error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid credentials' });
    }

    // Password correct — login user
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      name: user.name,
      email: user.email
    };

    if (user.role === 'admin') {
      res.redirect('/admin');
    } else {
      res.redirect('/dashboard');
    }
  });
});



// Handle Register
app.post('/register', async (req, res) => {
  const { username, password, name, email } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (username, password, role, name, email) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, 'user', name, email],
      function (err) {
        if (err) {
          console.error(err);
          res.render('register', { error: 'Username or email already taken' });
        } else {
          res.redirect('/login');
        }
      }
    );
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Something went wrong. Please try again.' });
  }
});





// Handle Edit Book
app.get('/edit-book/:id', isLoggedIn, isAdmin, (req, res) => {
  const bookId = req.params.id;

  db.get('SELECT * FROM books WHERE id = ?', [bookId], (err, book) => {
    if (err || !book) return res.status(404).send('Book not found');

    db.all('SELECT id, name FROM sections', (secErr, sections) => {
      if (secErr) return res.status(500).send('Error loading sections');

      res.render('edit_book', { book, sections, error: null });
    });
  });
});











// Handle Delete Book
app.post('/delete-book', isLoggedIn, isAdmin, (req, res) => {
  const { id } = req.body;
  db.run('DELETE FROM books WHERE id = ?', [id], function (err) {
    res.redirect('/admin');
  });
});





// Download route (after "payment")
app.get('/download/:id', isLoggedIn, (req, res) => {
  db.get('SELECT * FROM books WHERE id = ?', [req.params.id], (err, book) => {
    if (!book) return res.status(404).send('Book not found');
    res.download(path.join(__dirname, 'uploads', 'pdfs', book.pdf), book.title + '.pdf');
  });
});



//  USER _SECTIONS _
// USER DASHBOARD
app.get('/dashboard', isLoggedIn, (req, res) => {
  // First, get all sections
  db.all('SELECT * FROM sections', (err, sections) => {
    if (err) return res.status(500).send('Database error');

    // For each section, get its books
    const sectionPromises = sections.map(section => {
      return new Promise((resolve, reject) => {
        db.all('SELECT * FROM books WHERE section_id = ?', [section.id], (err, books) => {
          if (err) return reject(err);
          section.books = books; // Attach books to the section
          resolve();
        });
      });
    });

    Promise.all(sectionPromises)
      .then(() => {
        res.render('user_dashboard', { sections, user: req.user });
      })
      .catch(() => res.status(500).send('Database error'));
  });
});


// Show profile page
app.get('/profile', isLoggedIn, (req, res) => {
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.redirect('/login');
    res.render('profile', { user, success: null, error: null });
  });
});

// Handle profile update
app.post('/profile', isLoggedIn, (req, res) => {
  const { name, email } = req.body;
  db.run(
    'UPDATE users SET name = ?, email = ? WHERE id = ?',
    [name, email, req.user.id],
    function (err) {
      if (err) {
        db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (e, user) => {
          res.render('profile', { user, success: null, error: 'Update failed.' });
        });
      } else {
        // Update session data so nav and other pages have new info
        db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (e, user) => {
          req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
            name: user.name,
            email: user.email
          };
          res.render('profile', { user, success: 'Profile updated!', error: null });
        });
      }
    }
  );
});
// read_book
app.get('/read/:id', isLoggedIn, (req, res) => {
  const userId = req.session.user.id;
  const bookId = req.params.id;

  const planLimits = {
    free: 5,
    basic: 50,
    pro: 200,
    mega: Infinity
  };

  const userPlan = req.session.user.subscription_plan || 'free';
  const monthlyLimit = planLimits[userPlan];
  const alreadyRead = req.session.user.monthly_books_read || 0;

  // Check if the user exceeded the monthly limit
  if (alreadyRead >= monthlyLimit) {
    return res.redirect('/subscribe?limit_exceeded=true');
  }

  db.get('SELECT * FROM books WHERE id = ?', [bookId], (err, book) => {
    if (err || !book) return res.status(404).send('Book not found');

    // Increment the user's monthly_books_read
    db.run(`INSERT INTO book_history (user_id, book_id) VALUES (?, ?)`, [userId, bookId]);
    
    db.run(
      'UPDATE users SET monthly_books_read = monthly_books_read + 1 WHERE id = ?',
      [userId],
      (err) => {
        if (err) return res.status(500).send('Failed to update read count');

        // Refresh session data with updated read count
        db.get('SELECT * FROM users WHERE id = ?', [userId], (err, updatedUser) => {
          if (err) return res.status(500).send('Failed to fetch updated user');

          req.session.user = updatedUser;
          res.locals.user = updatedUser;

          req.session.save((err) => {
            if (err) console.error('Session save error:', err);
            res.render('read_book', { book });
          });
        });
      }
    );
  });
});



// BOOK HISTORY

app.get('/history', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const userId = req.session.user.id;

  const query = `
    SELECT bh.read_at, b.title, b.author, b.thumbnail
    FROM book_history bh
    JOIN books b ON bh.book_id = b.id
    WHERE bh.user_id = ?
    ORDER BY bh.read_at DESC
  `;

  db.all(query, [userId], (err, history) => {
    if (err) {
      console.error(err);
      return res.render('read_history', { history: [], error: 'Failed to load history.' });
    }

    res.render('read_history', { history });
  });
});


// Subscription route
app.get('/subscribe', isLoggedIn, (req, res) => {
  const user = req.session.user;
  const planLimits = { free: 5, basic: 50, pro: 200, mega: Infinity };
  const limit = planLimits[user.subscription_plan || 'free'];
  const read = user.monthly_books_read || 0;

  res.render('subscribe', {
    booksRead: read,
    remaining: Math.max(0, limit - read),
    plan: user.subscription_plan,
    query: req.query
  });
});


app.post('/subscribe', isLoggedIn, (req, res) => {
  // In real app: Integrate Stripe/PayPal here
  const endDate = new Date();
  endDate.setMonth(endDate.getMonth() + 1); // 1-month sub
  
  db.run(
    'UPDATE users SET is_subscribed = TRUE, subscription_end = ? WHERE id = ?',
    [endDate.toISOString(), req.user.id],
    (err) => {
      res.redirect('/dashboard');
    }
  );
});

// BUY SUBSCRIPTION


app.post('/create-checkout-session', isLoggedIn, async (req, res) => {
  const plan = req.body.plan;
  const plans = {
  basic: { name: 'Basic', price: 49900 },   // ₹499
  pro: { name: 'Pro', price: 99900 },       // ₹999
  mega: { name: 'Mega', price: 149900 }     // ₹1499
};


  if (!plans[plan]) return res.status(400).send('Invalid plan');

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    mode: 'payment',
    line_items: [
      {
        price_data: {
          currency: 'inr',
          product_data: {
            name: `${plans[plan].name} Subscription Plan`
          },
          unit_amount: plans[plan].price,
        },
        quantity: 1,
      }
    ],
    success_url: `${req.protocol}://${req.get('host')}/subscription-success?plan=${plan}`,
    cancel_url: `${req.protocol}://${req.get('host')}/pay-subscription?plan=${plan}`,
    metadata: {
      userId: req.session.user.id
    }
  });

  res.redirect(303, session.url);
});





app.get('/pay-subscription', isLoggedIn, (req, res) => {
  const plan = req.query.plan;
  const plans = {
    basic: { name: 'Basic', price: 499 },
    pro: { name: 'Pro', price: 999 },
    mega: { name: 'Mega', price: 1499 }
  };

  if (!plans[plan]) return res.status(400).send('Invalid plan');

  res.render('pay_subscription', {
    plan,
    price: plans[plan].price,
    planName: plans[plan].name
  });
});


app.get('/subscription-success', isLoggedIn, (req, res) => {
  const plan = req.query.plan;
  const planDurations = { basic: 1, pro: 1, mega: 1 };

  if (!planDurations[plan]) return res.status(400).send('Invalid plan');

  const endDate = new Date();
  endDate.setMonth(endDate.getMonth() + planDurations[plan]);

  db.run(
    `UPDATE users SET 
      subscription_plan = ?, 
      subscription_end = ?, 
      monthly_books_read = 0 
    WHERE id = ?`,
    [plan, endDate.toISOString(), req.session.user.id],
    (err) => {
      if (err) return res.status(500).send('Subscription update failed.');

      db.get('SELECT * FROM users WHERE id = ?', [req.session.user.id], (err, updatedUser) => {
        req.session.user = updatedUser;
        res.locals.user = updatedUser;
        req.session.save(() => {
          res.render('pay_success', { plan });
        });
      });
    }
  );
});




// Delete below


app.post('/process-subscription', isLoggedIn, (req, res) => {
  const plan = req.body.plan;
  const planDurations = { basic: 1, pro: 1, mega: 1 };

  if (!planDurations[plan]) return res.status(400).send('Invalid plan');

  const endDate = new Date();
  endDate.setMonth(endDate.getMonth() + planDurations[plan]);

  db.run(
    `UPDATE users SET 
      subscription_plan = ?, 
      subscription_end = ?, 
      monthly_books_read = 0 
    WHERE id = ?`,
    [plan, endDate.toISOString(), req.session.user.id],
    (err) => {
      if (err) return res.status(500).send('Subscription update failed.');
      db.get('SELECT * FROM users WHERE id = ?', [req.session.user.id], (err, updatedUser) => {
        req.session.user = updatedUser;
        res.locals.user = updatedUser;
        req.session.save(() => {
          res.render('pay_success', { plan });
        });
      });
    }
  );
});




// forget password

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// const nodemailer = require('nodemailer');


const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false, // false for port 587 (TLS)
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  }
});


app.get('/forgot-password', (req, res) => {
  res.render('forgot_password', {
    error: req.query.error || null,
    success: req.query.success || null,
  });
  
});


transporter.verify((error, success) => {
  if (error) {
    console.error('SMTP Connection Error:', error);
  } else {
    console.log('✅ SMTP Connected');
  }
});





app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.redirect('/forgot-password?error=Email is required');
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      console.error(err);
      return res.redirect('/forgot-password?error=Server error');
    }

    if (!user) {
      return res.redirect('/forgot-password?error=Email not found');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 3600000;

    db.run(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
      [token, expiry, user.id],
      async (err) => {
        if (err) {
          console.error(err);
          return res.redirect('/forgot-password?error=Database error');
        }

        const baseUrl = `${req.protocol}://${req.get('host')}`;
        const resetLink = `${baseUrl}/reset-password/${token}`;

        try {
          await transporter.sendMail({
            to: email,
            subject: 'Reset your password',
            html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
          });

          return res.redirect('/forgot-password?success=Reset link sent to your email.');

        } catch (emailErr) {
          console.error(emailErr);
          return res.redirect('/forgot-password?error=Failed to send email');
        }
      }
    );
  });
});




app.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  db.get(
    'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?',
    [token, Date.now()],
    (err, user) => {
      if (!user) return res.send('Invalid or expired token.');
      res.render('reset_password_form', { token });
    }
  );
});




app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  db.get(
    'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?',
    [token, Date.now()],
    async (err, user) => {
      if (!user) return res.send('Invalid or expired token.');

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      db.run(
        'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
        [hashedPassword, user.id],
        (err) => {
          if (err) return res.send('Error updating password.');
          res.send('Password reset successful! You can now <a href="/login">log in</a>.');
        }
      );
    }
  );
});


// For all 
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// In server.js
// const stripe = require('stripe')('your_stripe_key');

app.post('/subscribe', isLoggedIn, async (req, res) => {
  const { plan } = req.body;
  
  const prices = {
    basic: 'price_123',
    pro: 'price_456', 
    mega: 'price_789'
  };

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price: prices[plan],
      quantity: 1,
    }],
    mode: 'subscription',
    success_url: `${process.env.DOMAIN}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.DOMAIN}/cancel`,
  });

  res.redirect(303, session.url);
});



app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
