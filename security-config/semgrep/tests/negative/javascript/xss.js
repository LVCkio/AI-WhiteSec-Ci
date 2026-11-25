const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/hello', (req, res) => {
  // ok: team.js.xss-taint
  res.send(escapeHtml(req.query.name));
  // ok: team.js.xss-taint, team.js.xss-html-concat
  res.send('<h1>Hello</h1>');
});

function render(el, text) {
  // ok: team.js.xss-dom-sink
  el.innerHTML = '';
  // ok: team.js.xss-dom-sink
  el.textContent = text;
}

// ---- v4.1
function renderRow(container, name, formData) {
  // ok: team.js.xss-jquery-insert
  container.append('<li>static</li>');
  // ok: team.js.xss-jquery-insert
  container.append(document.createTextNode(name));
  // ok: team.js.xss-jquery-insert
  formData.append('name', name);
}
