const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  // ruleid: team.js.sqli-taint, team.js.sqli-string
  db.query("SELECT * FROM users WHERE id = " + id, (e, r) => res.json(r));
  // ruleid: team.js.sqli-string
  db.query(`SELECT * FROM orders WHERE owner = ${owner}`);
});

// ---- v4.1
async function findUser(pool, name, id) {
  // ruleid: team.js.sqli-dynamic-query
  await pool.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ruleid: team.js.sqli-dynamic-query
  await sequelize.query(`DELETE FROM sessions WHERE uid = ${id}`);
  // ruleid: team.js.sqli-dynamic-query
  return Sequelize.literal('(SELECT COUNT(*) FROM posts WHERE owner = ' + id + ')');
}

async function runQuery(db, sql) {
  // ruleid: team.js.audit.sql-api
  return db.query(sql);
}
