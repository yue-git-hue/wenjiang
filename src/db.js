"use strict";
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

fs.mkdirSync(path.join(__dirname, "../data"), { recursive: true });
const db = new Database(path.join(__dirname, "../data/wenjiang.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    phone      TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    name       TEXT DEFAULT '',
    company    TEXT DEFAULT '',
    status     TEXT DEFAULT 'inactive',
    plan       TEXT DEFAULT '',
    expires    TEXT,
    created    TEXT DEFAULT (datetime('now','localtime')),
    last_login TEXT,
    free_uses  INTEGER DEFAULT 0,
    month_uses INTEGER DEFAULT 0,
    month_year TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS orders (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER,
    out_trade_no TEXT UNIQUE,
    plan         TEXT,
    amount       REAL,
    days         INTEGER,
    status       TEXT DEFAULT 'pending',
    paid_at      TEXT,
    created      TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS usage_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    phone   TEXT,
    action  TEXT,
    ts      TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    file_name   TEXT,
    template    TEXT,
    status      TEXT DEFAULT 'pending',
    result_path TEXT,
    created_at  TEXT DEFAULT (datetime('now','localtime'))
  );
`);

module.exports = db;
