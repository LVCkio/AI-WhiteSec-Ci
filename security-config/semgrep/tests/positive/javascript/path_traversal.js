const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/file', (req, res) => {
  // ruleid: team.js.path-taint
  res.sendFile(path.join(__dirname, 'files', req.query.name));
  // ruleid: team.js.path-taint
  fs.readFile(req.params.file, (e, d) => res.send(d));
});

// ---- v4.1
function readUpload(name, res) {
  const data = fs.readFileSync(path.join(UPLOAD_DIR, name));
  fs.unlink(name, () => {});
  res.download(name);
}
