const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  // ok: team.js.sqli-taint, team.js.sqli-string
  db.query("SELECT * FROM users WHERE id = ?", [id]);
  const n = parseInt(req.query.n);
  // ok: team.js.sqli-taint
  db.query("SELECT * FROM users WHERE id = " + n);
});

// ---- v4.1
async function findUser(pool, name, cache, a, b) {
  // ok: team.js.sqli-dynamic-query
  await pool.query("SELECT * FROM users WHERE name = $1", [name]);
  // ok: team.js.sqli-dynamic-query
  const total = cache.get(a + b);
  return total;
}

async function runQuery(db, map, key) {
  // ok: team.js.audit.sql-api
  await db.query("SELECT 1");
  // ok: team.js.audit.sql-api
  return map.query(key);
}
