// db.js
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

if (!fs.existsSync('./data')) fs.mkdirSync('./data');

const db = new sqlite3.Database('./data/app.db');

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  owner_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);
`;

db.exec(schema, (err) => {
  if (err) {
    console.error('Error creando esquema:', err);
  } else {
    console.log('Base y tablas listas en ./data/app.db');
  }
  db.close();
});