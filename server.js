const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// This is intentionally weak for the challenge
const JWT_SECRET = 'jwt_challenge_123'; 

app.use(bodyParser.json());
app.use(express.static('public'));

// User database (in memory for simplicity)
const users = [
  { username: 'user', password: 'password123', role: 'user' },
  { username: 'admin', password: 'admin_secret_pwd', role: 'admin' }
];

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  
  // Create JWT token
  const token = jwt.sign(
    { username: user.username, role: user.role },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
  
  res.json({ token, message: 'Login successful' });
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  // VULNERABILITY: Loose JWT verification that allows "none" algorithm
  try {
    // First try to verify with the secret
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
    req.user = decoded;
    next();
  } catch (err) {
    // If that fails, try again but with different approach to handle "none" algorithm
    try {
      // Split the token manually
      const tokenParts = token.split('.');
      if (tokenParts.length === 3) {
        const header = JSON.parse(Buffer.from(tokenParts[0], 'base64').toString());
        
        // If algorithm is "none", trust the payload without verification
        if (header.alg === 'none') {
          const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
          req.user = payload;
          next();
          return;
        }
      }
      return res.status(403).json({ message: 'Invalid token' });
    } catch (error) {
      return res.status(403).json({ message: 'Invalid token' });
    }
  }
}

// API to list available files
app.get('/api/files', authenticateToken, (req, res) => {
  const userFiles = ['file1.txt', 'file2.txt'];
  
  if (req.user.role === 'admin') {
    userFiles.push('file3.txt'); // Admin-only file
  }
  
  res.json({ files: userFiles });
});

// API to get file content
app.get('/api/files/:filename', authenticateToken, (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'files', filename);
  
  // Security check - only admin can access file3.txt
  if (filename === 'file3.txt' && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied: Admin privileges required' });
  }
  
  // Basic path traversal protection
  if (!['file1.txt', 'file2.txt', 'file3.txt'].includes(filename)) {
    return res.status(400).json({ message: 'Invalid file requested' });
  }
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ message: 'File not found' });
    }
    res.json({ content: data });
  });
});

// Add CSS file endpoint
app.get('/css/style.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css');
  res.sendFile(path.join(__dirname, 'public', 'css', 'style.css'));
});

// Serve index.html for root path
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});