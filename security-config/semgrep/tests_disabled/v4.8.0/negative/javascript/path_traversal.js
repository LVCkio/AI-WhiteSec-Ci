const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/file', (req, res) => {
  // ok: team.js.path-taint
  res.sendFile(path.join(__dirname, 'files', path.basename(req.query.name)));
  // ok: team.js.path-taint
  fs.readFile(path.join(__dirname, 'static', 'index.html'), (e, d) => res.send(d));
});

// ---- v4.1
function readConfig(res) {
  // ok: team.js.audit.fs-path-api
  const data = fs.readFileSync("/etc/app/config.json");
  // ok: team.js.audit.fs-path-api
  res.sendFile("index.html");
  return data;
}

// ---- v4.2: duong dan ghep toan hang so
function serveIndex(res) {
  // ok: team.js.audit.fs-path-api
  res.sendFile(path.resolve('frontend/dist/frontend/index.html'));
  // ok: team.js.audit.fs-path-api
  return fs.readFileSync(path.join(__dirname, 'config.json'));
}
