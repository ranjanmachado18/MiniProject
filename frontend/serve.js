// Minimal static server for the frontend (no build step needed).
// Run: node serve.js   -> http://localhost:5500
const express = require('express');
const path = require('path');
const app = express();
app.use(express.static(__dirname));
app.listen(5500, () => console.log('Frontend on http://localhost:5500'));
