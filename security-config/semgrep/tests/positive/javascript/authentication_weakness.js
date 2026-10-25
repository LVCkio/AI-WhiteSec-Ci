const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

function auth(token, key, password, stored) {
  // ruleid: team.js.auth-jwt-unverified
  jwt.verify(token, key, { algorithms: ['none'] });
  // ruleid: team.js.auth-jwt-decode
  const claims = jwt.decode(token);
  // ruleid: team.js.auth-weak-password-hash
  const h = crypto.createHash('md5');
  return password === stored;
}

