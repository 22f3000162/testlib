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
  destination: (req, file, cb) => {
    if (file.fieldname === 'pdf') cb(null, './uploads/pdfs');
    else if (file.fieldname === 'thumbnail') cb(null, './uploads/thumbnails');
    else cb(null, './uploads');
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// --- Express Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(session({
  secret: 'some_strong_secret',
  resave: false,
  saveUninitialized: false
}));
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- Middleware ---
app.use(async (req, res, next) => {
  if (req.session?.user) req.user = req.session.user;
  else req.user = null;
  res.locals.user = req.user;
  next();
});

function isLoggedIn(req, res, next) {
  if (req.user) next();
  else res.redirect('/login');
}
function isAdmin(req, res, next) {
  if (req.user?.role === 'admin') next();
  else res.status(403).send('Access denied. Admins only.');
}

// --- Nodemailer Setup ---
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

transporter.verify((err, success) => {
  if (err) console.error('SMTP Error:', err);
  else console.log('SMTP Connected');
});

// --- ROUTES ---
// Home Page
app.get('/', async (req, res) => {
  if (req.session?.user) return res.redirect('/dashboard');
  try {
    const sectionsRes = await db.execute('SELECT * FROM sections');
    const sections = sectionsRes.rows;

    for (const section of sections) {
      const booksRes = await db.execute('SELECT * FROM books WHERE section_id = ?', [section.id]);
      section.books = booksRes.rows;
    }

    res.render('index', { sections, user: null });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Login/Register
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userRes = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    const user = userRes.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.user = user;
    res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Server error' });
  }
});

app.get('/register', (req, res) => res.render('register', { error: null }));
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

// Dashboard
app.get('/dashboard', isLoggedIn, async (req, res) => {
  try {
    const sectionsRes = await db.execute('SELECT * FROM sections');
    const sections = sectionsRes.rows;

    for (const section of sections) {
      const booksRes = await db.execute('SELECT * FROM books WHERE section_id = ?', [section.id]);
      section.books = booksRes.rows;
    }

    res.render('user_dashboard', { sections, user: req.user });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Admin
app.get('/admin', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const booksRes = await db.execute(`
      SELECT books.*, sections.name AS section_name
      FROM books JOIN sections ON books.section_id = sections.id
    `);
    const usersRes = await db.execute('SELECT * FROM users');
    res.render('admin_dashboard', { books: booksRes.rows, users: usersRes.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// Add Book
app.get('/add-book', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const sectionsRes = await db.execute('SELECT id, name FROM sections');
    res.render('add_book', { error: null, sections: sectionsRes.rows });
  } catch (err) {
    res.render('add_book', { error: 'Failed to load sections', sections: [] });
  }
});

app.post('/add-book', isLoggedIn, isAdmin, upload.fields([{ name: 'pdf' }, { name: 'thumbnail' }]), async (req, res) => {
  try {
    const { title, author, section_id } = req.body;
    const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : null;
    const thumbnail = req.files['thumbnail'] ? req.files['thumbnail'][0].filename : null;
    await db.execute('INSERT INTO books (title, author, pdf, thumbnail, section_id) VALUES (?, ?, ?, ?, ?)',
      [title, author, pdf, thumbnail, section_id]
    );
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to add book');
  }
});

// Edit Book
app.get('/edit-book/:id', isLoggedIn, isAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const bookRes = await db.execute('SELECT * FROM books WHERE id = ?', [id]);
    const book = bookRes.rows[0];
    if (!book) return res.status(404).send('Book not found');

    const sectionsRes = await db.execute('SELECT id, name FROM sections');
    res.render('edit_book', { book, sections: sectionsRes.rows, error: null });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/edit-book/:id', isLoggedIn, isAdmin, upload.fields([{ name: 'pdf' }, { name: 'thumbnail' }]), async (req, res) => {
  const id = req.params.id;
  const { title, author } = req.body;
  try {
    const bookRes = await db.execute('SELECT * FROM books WHERE id = ?', [id]);
    const book = bookRes.rows[0];
    if (!book) return res.status(404).send('Book not found');

    const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : book.pdf;
    const thumbnail = req.files['thumbnail'] ? req.files['thumbnail'][0].filename : book.thumbnail;

    await db.execute('UPDATE books SET title = ?, author = ?, pdf = ?, thumbnail = ? WHERE id = ?',
      [title, author, pdf, thumbnail, id]
    );
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to update book');
  }
});

// Delete Book
app.get('/delete-book/:id', isLoggedIn, isAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await db.execute('DELETE FROM books WHERE id = ?', [id]);
    res.redirect('/admin');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to delete book');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Password Reset
app.get('/forgot-password', (req, res) => res.render('forgot_password', { error: null }));
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userRes = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = userRes.rows[0];
    if (!user) return res.render('forgot_password', { error: 'Email not found' });

    const token = crypto.randomBytes(20).toString('hex');
    const expiry = Date.now() + 3600000;
    await db.execute('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?', [token, expiry, email]);

    const resetLink = `${req.protocol}://${req.get('host')}/reset-password/${token}`;
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Password Reset',
      html: `Click <a href="${resetLink}">here</a> to reset your password.`
    });
    res.send('Password reset email sent');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const userRes = await db.execute('SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?', [token, Date.now()]);
    const user = userRes.rows[0];
    if (!user) return res.send('Invalid or expired token');
    res.render('reset_password', { token, error: null });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const userRes = await db.execute('SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?', [token, Date.now()]);
    const user = userRes.rows[0];
    if (!user) return res.send('Invalid or expired token');

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?', [hashedPassword, user.id]);
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Stripe Example
app.post('/create-payment-intent', isLoggedIn, async (req, res) => {
  const { amount } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Number(amount) * 100,
      currency: 'usd',
      automatic_payment_methods: { enabled: true }
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error(err);
    res.status(500).send('Payment error');
  }
});

// --- Start Server ---
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
