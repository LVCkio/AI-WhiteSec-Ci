const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/ping', (req, res) => {
  // ruleid: team.js.cmdi-taint, team.js.cmd-shell
  cp.exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));
});

// ---- v4.1
function build(cmd, target) {
  // ruleid: team.js.audit.process-api
  child.exec(cmd);
  // ruleid: team.js.audit.process-api
  execSync(target);
}
