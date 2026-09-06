// db.js
// VULNERABILITY NOTE: This module exposes a raw string-concatenation query
// helper (rawQuery) that several routes use on purpose, to create classic
// SQL Injection (CWE-89) points for scanning practice. A "safe" parameterized
// helper (paramQuery) is also provided for the routes that are NOT meant to
// be injectable, so you can compare scanner results between the two.

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'vulnbank.sqlite');
const db = new sqlite3.Database(DB_PATH);

function init() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password TEXT,        -- VULNERABILITY: stored in PLAINTEXT (CWE-256)
      full_name TEXT,
      role TEXT DEFAULT 'user',
      avatar_path TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      account_number TEXT,  -- VULNERABILITY: sequential/predictable (CWE-330 style enumeration)
      balance REAL DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_account INTEGER,
      to_account INTEGER,
      amount REAL,
      note TEXT,             -- VULNERABILITY: rendered unescaped on frontend -> Stored XSS (CWE-79)
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed data (idempotent-ish for a demo project)
    db.get(`SELECT COUNT(*) as c FROM users`, (err, row) => {
      if (row && row.c === 0) {
        const seedUsers = [
          ['admin', 'admin@vulnbank.local', 'admin123', 'Site Administrator', 'admin'],
          ['alice', 'alice@vulnbank.local', 'alice123', 'Alice Anderson', 'user'],
          ['bob', 'bob@vulnbank.local', 'bob123', 'Bob Brown', 'user'],
        ];
        const stmt = db.prepare(`INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)`);
        seedUsers.forEach(u => stmt.run(u));
        stmt.finalize(() => {
          const acctStmt = db.prepare(`INSERT INTO accounts (user_id, account_number, balance) VALUES (?, ?, ?)`);
          acctStmt.run(1, 'ACC10001', 500000);
          acctStmt.run(2, 'ACC10002', 15420.5);
          acctStmt.run(3, 'ACC10003', 8300.75);
          acctStmt.finalize();
        });
      }
    });
  });
}

// Intentionally unsafe: caller builds SQL with string concatenation.
function rawQuery(sql, cb) {
  db.all(sql, cb);
}

function paramQuery(sql, params, cb) {
  db.all(sql, params, cb);
}

function run(sql, params, cb) {
  db.run(sql, params, cb);
}

module.exports = { db, init, rawQuery, paramQuery, run };
