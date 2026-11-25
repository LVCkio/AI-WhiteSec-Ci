const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

// ok: team.js.hardcoded-secret
const API_URL = "https://api.example.com";
// ok: team.js.hardcoded-secret
const config2 = { user: "app", password: process.env.DB_PASSWORD };

function login(username, password, stored) {
  // ok: team.js.hardcoded-password-compare
  if (username === "admin") { return bcrypt.compareSync(password, stored); }
  // ok: team.js.hardcoded-password-compare
  return password === "";
}

// ---- v4.2: kiem tra gia tri rong, khong phai mat khau viet cung (Juice Shop changePassword)
function changePassword(newPassword) {
  // ok: team.js.hardcoded-password-compare
  if (!newPassword || newPassword === 'undefined') { return false; }
  return true;
}

// ok: team.js.hardcoded-secret
const password = "changeme";
// ok: team.js.hardcoded-secret
const cfg = { jwtSecret: "secret" };

// ---- v4.8.0: gia tri gia lap (co khoang trang, snake_case chu thuong) va literal placeholder trong jwt.sign
// ok: team.js.hardcoded-secret
app.use(session({ resave: false, secret: 'keyboard cat' }));
// ok: team.js.hardcoded-secret
const labels = { 'form.password.placeholder': 'Confirm password' };
// ok: team.js.hardcoded-secret
const clients = { foo: { id: 'foo_id', secret: 'foo_secret' } };
// ok: team.js.hardcoded-secret
const errors = { PasswordStrengthError: 'password_strength_error' };
// ok: team.js.hardcoded-secret
const t2 = jwt.sign({ aud: 'my-audience' }, 'secret');
