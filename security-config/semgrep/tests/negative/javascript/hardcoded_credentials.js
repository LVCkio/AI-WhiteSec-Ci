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
