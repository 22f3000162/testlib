import 'dotenv/config';
import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import multer from 'multer';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import expressLayouts from 'express-ejs-layouts';
import nodemailer from 'nodemailer';
import Stripe from 'stripe';
import { createClient } from '@libsql/client';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const __dirname = path.resolve();

// --- Turso DB Client ---
const db = createClient({
  url: process.env.TURSO_DB_URL,
  authToken: process.env.TURSO_DB_KEY
});

// --- File Upload Setup ---
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');
if (!fs.existsSync('./uploads/pdfs')) fs.mkdirSync('./uploads/pdfs');
if (!fs.existsSync('./uploads/thumbnails')) fs.mkdirSync('./uploads/thumbnails');

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

// --- Express Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'some_strong_secret',
  resave: false,
  saveUninitialized: false,
  // cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.set('view engine', 'ejs');
app.use(expressLayouts); 
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Middleware Functions ---
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

// Add subscription check middleware
const checkSubscription = (req, res, next) => {
  if (!req.user.is_subscribed && req.user.books_read >= 5) {
    return res.redirect('/subscribe');
  }
  next();
};

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

// --- Nodemailer Setup ---
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false, // false for port 587 (TLS)
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  }
});

transporter.verify((error, success) => {
  if (error) {
    console.error('SMTP Connection Error:', error);
  } else {
    console.log('✅ SMTP Connected');
  }
});

// --- ROUTES ---

// Home Page
app.get('/', async (req, res) => {
  // Step 1: Check login
  if (req.session && req.session.user) {
    return res.redirect('/dashboard'); // original behavior preserved
  }
  
  try {
    // Step 2: Load data for guests
    const sectionsResult = await db.execute('SELECT * FROM sections');
    const sections = sectionsResult.rows;
    
    // Load books for each section
    const sectionPromises = sections.map(async (section) => {
      const booksResult = await db.execute('SELECT * FROM books WHERE section_id = ?', [section.id]);
      section.books = booksResult.rows;
      return section;
    });
    
    await Promise.all(sectionPromises);
    
    res.render('index', {
      sections,
      user: null // explicitly no session user
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Login Page
app.get('/login', (req, res) => res.render('login', { error: null}));

// Register Page
app.get('/register', (req, res) => res.render('register', { error: null }));

// Books Page
app.get('/books', async (req, res) => {
  try {
    const booksResult = await db.execute('SELECT * FROM books');
    res.render('books', { books: booksResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Admin Dashboard
app.get('/admin', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const bookQuery = `
      SELECT books.*, sections.name AS section_name
      FROM books
      JOIN sections ON books.section_id = sections.id
    `;
    const booksResult = await db.execute(bookQuery);
    const usersResult = await db.execute('SELECT * FROM users');
    
    res.render('admin_dashboard', { 
      books: booksResult.rows, 
      users: usersResult.rows 
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Add Section Page
app.get('/add-section', isLoggedIn, isAdmin, (req, res) => {
  res.render('add_section', { error: null });
});

// Handle Add Section
app.post('/add-section', isLoggedIn, isAdmin, async (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return res.render('add_section', { error: 'Section name is required.' });
  }
  
  try {
    await db.execute('INSERT INTO sections (name, description) VALUES (?, ?)', [name, description]);
    res.redirect('/add-book'); // or wherever makes sense in your flow
  } catch (err) {
    console.error(err);
    res.render('add_section', { error: 'Error adding section. It may already exist.' });
  }
});

// GET: Show add book form with all available sections
app.get('/add-book', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const sectionsResult = await db.execute('SELECT id, name FROM sections');
    res.render('add_book', { error: null, sections: sectionsResult.rows });
  } catch (err) {
    console.error(err);
    res.render('add_book', { error: 'Failed to load sections.', sections: [] });
  }
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
  async (req, res) => {
    const { title, author, section_id } = req.body;
    const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : null;
    const thumbnail = req.files['thumbnail'] ? req.files['thumbnail'][0].filename : null;
    
    // Validate inputs
    if (!title || !author || !section_id || !pdf || !thumbnail) {
      try {
        const sectionsResult = await db.execute('SELECT id, name FROM sections');
        return res.render('add_book', {
          error: 'All fields are required, including section.',
          sections: sectionsResult.rows || []
        });
      } catch (err) {
        return res.render('add_book', {
          error: 'All fields are required, including section.',
          sections: []
        });
      }
    }
    
    try {
      // Save book to DB
      await db.execute(
        'INSERT INTO books (title, author, pdf, thumbnail, section_id) VALUES (?, ?, ?, ?, ?)',
        [title, author, pdf, thumbnail, section_id]
      );
      res.redirect('/admin'); // or wherever you want
    } catch (err) {
      console.error(err);
      try {
        const sectionsResult = await db.execute('SELECT id, name FROM sections');
        res.render('add_book', {
          error: 'Error saving book. Try again.',
          sections: sectionsResult.rows || []
        });
      } catch (sectionsErr) {
        res.render('add_book', {
          error: 'Error saving book. Try again.',
          sections: []
        });
      }
    }
  }
);

// Edit BOOK - GET
app.get('/edit-book/:id', isLoggedIn, isAdmin, async (req, res) => {
  const bookId = req.params.id;
  try {
    const bookResult = await db.execute('SELECT * FROM books WHERE id = ?', [bookId]);
    const book = bookResult.rows[0];
    
    if (!book) return res.status(404).send('Book not found');
    
    const sectionsResult = await db.execute('SELECT id, name FROM sections');
    res.render('edit_book', { book, sections: sectionsResult.rows, error: null });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading sections');
  }
});

// Edit BOOK - POST
app.post('/edit-book/:id',
  isLoggedIn,
  isAdmin,
  upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'thumbnail', maxCount: 1 }
  ]),
  async (req, res) => {
    const { title, author } = req.body;
    const id = req.params.id;
    
    try {
      const bookResult = await db.execute('SELECT * FROM books WHERE id = ?', [id]);
      const book = bookResult.rows[0];
      
      if (!book) return res.status(404).send('Book not found');
      
      const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : book.pdf;
      const thumbnail = req.files['thumbnail'] ? req.files['thumbnail'][0].filename : book.thumbnail;
      
      await db.execute(
        'UPDATE books SET title = ?, author = ?, pdf = ?, thumbnail = ? WHERE id = ?',
        [title, author, pdf, thumbnail, id]
      );
      
      res.redirect('/admin');
    } catch (err) {
      console.error(err);
      try {
        const sectionsResult = await db.execute('SELECT id, name FROM sections');
        res.render('edit_book', { 
          book: { id, title, author }, 
          sections: sectionsResult.rows,
          error: 'Error updating book.' 
        });
      } catch (sectionsErr) {
        res.render('edit_book', { 
          book: { id, title, author }, 
          sections: [],
          error: 'Error updating book.' 
        });
      }
    }
  }
);

// Users Page (for admin)
app.get('/users', async (req, res) => {
  try {
    const usersResult = await db.execute('SELECT * FROM users');
    res.render('users', { users: usersResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Handle Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const userResult = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    const user = userResult.rows[0];
    
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
      email: user.email,
      subscription_plan: user.subscription_plan,
      monthly_books_read: user.monthly_books_read,
      is_subscribed: user.is_subscribed
    };
    
    if (user.role === 'admin') {
      res.redirect('/admin');
    } else {
      res.redirect('/dashboard');
    }
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Something went wrong. Try again.' });
  }
});

// Handle Register
app.post('/register', async (req, res) => {
  const { username, password, name, email } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute(
      'INSERT INTO users (username, password, role, name, email) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, 'user', name, email]
    );
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Username or email already taken' });
  }
});

// Handle Delete Book
app.post('/delete-book', isLoggedIn, isAdmin, async (req, res) => {
  const { id } = req.body;
  try {
    await db.execute('DELETE FROM books WHERE id = ?', [id]);
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.redirect('/admin');
  }
});

// Download route (after "payment")
app.get('/download/:id', isLoggedIn, async (req, res) => {
  try {
    const bookResult = await db.execute('SELECT * FROM books WHERE id = ?', [req.params.id]);
    const book = bookResult.rows[0];
    
    if (!book) return res.status(404).send('Book not found');
    
    res.download(path.join(__dirname, 'uploads', 'pdfs', book.pdf), book.title + '.pdf');
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// USER DASHBOARD
app.get('/dashboard', isLoggedIn, async (req, res) => {
  try {
    // First, get all sections
    const sectionsResult = await db.execute('SELECT * FROM sections');
    const sections = sectionsResult.rows;
    
    // For each section, get its books
    const sectionPromises = sections.map(async (section) => {
      const booksResult = await db.execute('SELECT * FROM books WHERE section_id = ?', [section.id]);
      section.books = booksResult.rows; // Attach books to the section
      return section;
    });
    
    await Promise.all(sectionPromises);
    res.render('user_dashboard', { sections, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Show profile page
app.get('/profile', isLoggedIn, async (req, res) => {
  try {
    const userResult = await db.execute('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const user = userResult.rows[0];
    
    if (!user) return res.redirect('/login');
    res.render('profile', { user, success: null, error: null });
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

// Handle profile update
app.post('/profile', isLoggedIn, async (req, res) => {
  const { name, email } = req.body;
  
  try {
    await db.execute(
      'UPDATE users SET name = ?, email = ? WHERE id = ?',
      [name, email, req.user.id]
    );
    
    // Update session data so nav and other pages have new info
    const userResult = await db.execute('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const user = userResult.rows[0];
    
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      name: user.name,
      email: user.email,
      subscription_plan: user.subscription_plan,
      monthly_books_read: user.monthly_books_read,
      is_subscribed: user.is_subscribed
    };
    
    res.render('profile', { user, success: 'Profile updated!', error: null });
  } catch (err) {
    console.error(err);
    try {
      const userResult = await db.execute('SELECT * FROM users WHERE id = ?', [req.user.id]);
      const user = userResult.rows[0];
      res.render('profile', { user, success: null, error: 'Update failed.' });
    } catch (userErr) {
      res.render('profile', { user: req.user, success: null, error: 'Update failed.' });
    }
  }
});

// read_book
app.get('/read/:id', isLoggedIn, async (req, res) => {
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
  
  try {
    const bookResult = await db.execute('SELECT * FROM books WHERE id = ?', [bookId]);
    const book = bookResult.rows[0];
    
    if (!book) return res.status(404).send('Book not found');
    
    // Increment the user's monthly_books_read
    await db.execute('INSERT INTO book_history (user_id, book_id) VALUES (?, ?)', [userId, bookId]);
    
    await db.execute(
      'UPDATE users SET monthly_books_read = monthly_books_read + 1 WHERE id = ?',
      [userId]
    );
    
    // Refresh session data with updated read count
    const updatedUserResult = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    const updatedUser = updatedUserResult.rows[0];
    
    req.session.user = updatedUser;
    res.locals.user = updatedUser;
    
    res.render('read_book', { book });
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to update read count');
  }
});

// BOOK HISTORY
app.get('/history', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  
  const userId = req.session.user.id;
  const query = `
    SELECT bh.read_at, b.title, b.author, b.thumbnail
    FROM book_history bh
    JOIN books b ON bh.book_id = b.id
    WHERE bh.user_id = ?
    ORDER BY bh.read_at DESC
  `;
  
  try {
    const historyResult = await db.execute(query, [userId]);
    res.render('read_history', { history: historyResult.rows });
  } catch (err) {
    console.error(err);
    res.render('read_history', { history: [], error: 'Failed to load history.' });
  }
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

// First /subscribe POST route (simple subscription)
app.post('/subscribe', isLoggedIn, async (req, res) => {
  // In real app: Integrate Stripe/PayPal here
  const endDate = new Date();
  endDate.setMonth(endDate.getMonth() + 1); // 1-month sub
  
  try {
    await db.execute(
      'UPDATE users SET is_subscribed = TRUE, subscription_end = ? WHERE id = ?',
      [endDate.toISOString(), req.user.id]
    );
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard');
  }
});

// **MISSING ENDPOINT 1** - BUY SUBSCRIPTION - Create Stripe Checkout Session
app.post('/create-checkout-session', isLoggedIn, async (req, res) => {
  const plan = req.body.plan;
  const plans = {
    basic: { name: 'Basic', price: 49900 },   // ₹499
    pro: { name: 'Pro', price: 99900 },       // ₹999
    mega: { name: 'Mega', price: 149900 }     // ₹1499
  };
  
  if (!plans[plan]) return res.status(400).send('Invalid plan');
  
  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).send('Payment error');
  }
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

// **MISSING ENDPOINT 2** - Subscription Success Page
app.get('/subscription-success', isLoggedIn, async (req, res) => {
  const plan = req.query.plan;
  const planDurations = { basic: 1, pro: 1, mega: 1 };
  
  if (!planDurations[plan]) return res.status(400).send('Invalid plan');
  
  const endDate = new Date();
  endDate.setMonth(endDate.getMonth() + planDurations[plan]);
  
  try {
    await db.execute(
      `UPDATE users SET 
        subscription_plan = ?, 
        subscription_end = ?, 
        monthly_books_read = 0 
      WHERE id = ?`,
      [plan, endDate.toISOString(), req.session.user.id]
    );
    
    const updatedUserResult = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    const updatedUser = updatedUserResult.rows[0];
    
    req.session.user = updatedUser;
    res.locals.user = updatedUser;
    
    res.render('pay_success', { plan });
  } catch (err) {
    console.error(err);
    res.status(500).send('Subscription update failed.');
  }
});

// Process subscription (you marked "Delete below" but keeping for compatibility)
app.post('/process-subscription', isLoggedIn, async (req, res) => {
  const plan = req.body.plan;
  const planDurations = { basic: 1, pro: 1, mega: 1 };
  
  if (!planDurations[plan]) return res.status(400).send('Invalid plan');
  
  const endDate = new Date();
  endDate.setMonth(endDate.getMonth() + planDurations[plan]);
  
  try {
    await db.execute(
      `UPDATE users SET 
        subscription_plan = ?, 
        subscription_end = ?, 
        monthly_books_read = 0 
      WHERE id = ?`,
      [plan, endDate.toISOString(), req.session.user.id]
    );
    
    const updatedUserResult = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    const updatedUser = updatedUserResult.rows[0];
    
    req.session.user = updatedUser;
    res.locals.user = updatedUser;
    
    res.render('pay_success', { plan });
  } catch (err) {
    console.error(err);
    res.status(500).send('Subscription update failed.');
  }
});

// forgot password GET
app.get('/forgot-password', (req, res) => {
  res.render('forgot_password', {
    error: req.query.error || null,
    success: req.query.success || null,
  });
});

// forgot password POST
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.redirect('/forgot-password?error=Email is required');
  }
  
  try {
    const userResult = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = userResult.rows[0];
    
    if (!user) {
      return res.redirect('/forgot-password?error=Email not found');
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 3600000;
    
    await db.execute(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
      [token, expiry, user.id]
    );
    
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const resetLink = `${baseUrl}/reset-password/${token}`;
    
    await transporter.sendMail({
      to: email,
      subject: 'Reset your password',
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
    });
    
    res.redirect('/forgot-password?success=Reset link sent to your email.');
  } catch (emailErr) {
    console.error(emailErr);
    res.redirect('/forgot-password?error=Failed to send email');
  }
});

app.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  
  try {
    const userResult = await db.execute(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?',
      [token, Date.now()]
    );
    const user = userResult.rows[0];
    
    if (!user) return res.send('Invalid or expired token.');
    res.render('reset_password_form', { token });
  } catch (err) {
    console.error(err);
    res.send('Database error.');
  }
});

app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  
  try {
    const userResult = await db.execute(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?',
      [token, Date.now()]
    );
    const user = userResult.rows[0];
    
    if (!user) return res.send('Invalid or expired token.');
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
      [hashedPassword, user.id]
    );
    
    res.send('Password reset successful! You can now <a href="/login">log in</a>.');
  } catch (err) {
    console.error(err);
    res.send('Error updating password.');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// **MISSING ENDPOINT 3** - Second /subscribe POST route (Stripe integration)
app.post('/subscribe-stripe', isLoggedIn, async (req, res) => {
  const { plan } = req.body;
  const prices = {
    basic: process.env.STRIPE_BASIC_PRICE_ID || 'price_123',
    pro: process.env.STRIPE_PRO_PRICE_ID || 'price_456', 
    mega: process.env.STRIPE_MEGA_PRICE_ID || 'price_789'
  };
  
  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).send('Payment error');
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
