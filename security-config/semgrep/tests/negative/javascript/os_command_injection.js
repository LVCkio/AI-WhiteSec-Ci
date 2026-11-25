const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/ping', (req, res) => {
  // ok: team.js.cmdi-taint, team.js.cmd-shell
  cp.execFile('ping', ['-c', '1', req.query.host]);
  // ok: team.js.cmd-shell, team.js.cmdi-taint
  cp.exec('uptime');
});

// ---- v4.1
function build(text) {
  // ok: team.js.audit.process-api
  cp.exec("make all");
  // ok: team.js.audit.process-api
  const m = /a(b)/.exec(text);
  return m;
}
