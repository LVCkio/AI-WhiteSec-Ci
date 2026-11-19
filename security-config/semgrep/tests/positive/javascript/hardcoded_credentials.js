const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

// ruleid: team.js.hardcoded-secret
const JWT_SECRET = "s3cr3t-key-123";
// ruleid: team.js.hardcoded-secret
const config = { user: "app", password: "hunter22" };
// ruleid: team.js.hardcoded-secret
const tok = jwt.sign({ sub: 1 }, "another-secret");

function login(username, password) {
  // ruleid: team.js.hardcoded-password-compare
  return username === "admin" && password === "Winter3708@";
}

// ---- v4.8.0: khoa PEM co khoang trang van phai bao; gia tri ngau nhien khong phai snake_case van bao
// ruleid: team.js.hardcoded-secret
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDNwqLEe9wgTXCb\n-----END RSA PRIVATE KEY-----';
// ruleid: team.js.hardcoded-secret
const settings = { clientSecret: 'q8Zr2LxW7vTn' };
// ruleid: team.js.hardcoded-secret
const t3 = jwt.verify(token, 'Zx81-signing-Key');
