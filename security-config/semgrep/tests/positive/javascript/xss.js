const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.get('/hello', (req, res) => {
  // ruleid: team.js.xss-taint, team.js.xss-html-concat
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

function render(el, html) {
  // ruleid: team.js.xss-dom-sink
  el.innerHTML = html;
}

// ---- v4.1
function renderRow(container, name) {
  // ruleid: team.js.xss-jquery-insert
  container.append('<li>' + name + '</li>');
  // ruleid: team.js.xss-jquery-insert
  $('#list').prepend(html);
}
