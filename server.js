const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));

// In-memory store for demo purposes
const users = {};

// Home page
app.get('/', (req, res) => {
  if (req.session.authenticated) {
    return res.send('Logged in');
  }
  res.redirect('/login');
});

// Registration
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    return res.send('User already exists');
  }
  const hashed = await bcrypt.hash(password, 10);
  const secret = speakeasy.generateSecret({ length: 20 });
  users[username] = { password: hashed, secret: secret.base32 };
  const otpauth = secret.otpauth_url;
  QRCode.toDataURL(otpauth, (err, data_url) => {
    res.render('secret', { secret: secret.base32, qr: data_url });
  });
});

// Login
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user) {
    return res.send('Invalid credentials');
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.send('Invalid credentials');
  }
  req.session.tempUser = username;
  res.redirect('/verify');
});

// Verify TOTP
app.get('/verify', (req, res) => {
  if (!req.session.tempUser) {
    return res.redirect('/login');
  }
  res.render('verify');
});

app.post('/verify', (req, res) => {
  const { token } = req.body;
  const username = req.session.tempUser;
  const user = users[username];
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: 'base32',
    token
  });
  if (verified) {
    req.session.authenticated = true;
    req.session.user = username;
    delete req.session.tempUser;
    return res.redirect('/');
  }
  res.send('Invalid token');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
