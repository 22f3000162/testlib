import 'dotenv/config';
import { createClient } from "@libsql/client";
import bcrypt from "bcrypt";

const hashedPassword = bcrypt.hashSync('1234', 10); // init setup

const db = createClient({
  url: process.env.TURSO_DB_URL,
  authToken: process.env.TURSO_DB_KEY
});

async function initDB() {
  try {
    // 1. Users Table
    await db.execute(`
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
      );
    `);

    // 2. Sections Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS sections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. Books Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        pdf TEXT NOT NULL UNIQUE,
        thumbnail TEXT NOT NULL UNIQUE,
        section_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE SET NULL ON UPDATE CASCADE
      );
    `);

    // 4. Nodemailer Config Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS nodemailer_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        smtp_host TEXT NOT NULL,
        smtp_port INTEGER NOT NULL,
        smtp_user TEXT NOT NULL,
        smtp_pass TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 5. Book History Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS book_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        book_id INTEGER NOT NULL,
        read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
      );
    `);

    // 6. Create Default Admin User if none exists
    const res = await db.execute(`SELECT COUNT(*) as count FROM users;`);
    const count = res.rows[0].count;
    if (count === 0) {
      await db.execute(
        `INSERT INTO users (username, password, role, name, email) VALUES (?, ?, ?, ?, ?);`,
        ['admin', hashedPassword, 'admin', 'Library Admin', 'admin@library.com']
      );
      console.log('✅ Default admin created');
      console.log('   Username: admin');
      console.log('   Password: 1234');
    }

    console.log("✅ Database initialized successfully!");
  } catch (err) {
    console.error("DB init error:", err);
  }
}

// Run init
initDB();

export default db;
