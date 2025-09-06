const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const hashedPassword = bcrypt.hashSync('1234', 10); // synchronous for init setup

const db = new sqlite3.Database(path.join(__dirname, 'library.db'), (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database');
});

db.serialize(() => {
  // 1. Users Table
// 1. Users Table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    name TEXT,
    email TEXT UNIQUE,
    subscription_plan TEXT DEFAULT 'free' CHECK(subscription_plan IN ('free', 'basic', 'pro', 'mega')),
    monthly_books_read INTEGER DEFAULT 0 CHECK(monthly_books_read >= 0),
    subscription_end DATE,
    reset_token TEXT,
    reset_token_expiry INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);


  // 2. Sections Table
  db.run(`
    CREATE TABLE IF NOT EXISTS sections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 3. Books Table
  db.run(`
    CREATE TABLE IF NOT EXISTS books (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      pdf TEXT NOT NULL UNIQUE,
      thumbnail TEXT NOT NULL UNIQUE,
      section_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE SET NULL ON UPDATE CASCADE
    )
  `);

  // 4. Nodemailer Config Table
  db.run(`
    CREATE TABLE IF NOT EXISTS nodemailer_config (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      smtp_host TEXT NOT NULL,
      smtp_port INTEGER NOT NULL,
      smtp_user TEXT NOT NULL,
      smtp_pass TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 5. Book History Table
  db.run(`
    CREATE TABLE IF NOT EXISTS book_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      book_id INTEGER NOT NULL,
      read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
    )
  `);


  // 6. Create Default Admin User
  db.get(`SELECT COUNT(*) AS count FROM users`, (err, row) => {
    if (!err && row.count === 0) {

db.run(
  `INSERT INTO users 
   (username, password, role, name, email) 
   VALUES (?, ?, ?, ?, ?)`,
  ['admin', hashedPassword, 'admin', 'Library Admin', 'admin@library.com'],
  (err) => {
    if (!err) {
      console.log('✅ Default admin created');
      console.log('   Username: admin');
      console.log('   Password: 1234');
    }
  }
);
    }
  });
});

module.exports = db;
