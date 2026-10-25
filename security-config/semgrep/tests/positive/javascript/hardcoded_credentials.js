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
