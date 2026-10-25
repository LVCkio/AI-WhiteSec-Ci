const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

function auth(token, key, password, stored, name) {
  // ok: team.js.auth-jwt-unverified, team.js.auth-jwt-decode
  jwt.verify(token, key, { algorithms: ['HS256'] });
  // ok: team.js.auth-weak-password-hash
  const s = crypto.createHash('sha256');
  const lastDot = name.lastIndexOf('.'); if (lastDotPosition !== -1) { return false; }
  if (tokenType === 'bearer') { return false; }
  return crypto.timingSafeEqual(Buffer.from(password), Buffer.from(stored));
}

