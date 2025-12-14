import sqlite3 from "sqlite3";
import fs from "fs";

sqlite3.verbose();

export const db = new sqlite3.Database("./matchroom.sqlite");

export function initDb() {
  const schema = fs.readFileSync(new URL("./schema.sql", import.meta.url), "utf8");
  db.exec(schema);
}

export function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

export function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

export function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}
