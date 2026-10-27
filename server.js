// ============================================
// RD INFRO TECHNOLOGY - Web Development Internship
// Tasks: 4 (Backend), 5 (Database), 6 (Auth)
// ============================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'rdinfro_secret_2026';

// ===== Middleware =====
app.use(cors());
app.use(express.json());

// ===== Task 5: SQLite Database =====
const db = new Database('./database.sqlite');

// Users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    joined TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Contact messages table
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Projects table
db.exec(`
  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    tech TEXT NOT NULL,
    github TEXT,
    live TEXT
  );
`);

// ===== Seed Default Projects =====
const projectCount = db.prepare('SELECT COUNT(*) AS total FROM projects').get().total;
if (projectCount === 0) {
  const insertProject = db.prepare(
    'INSERT INTO projects (title, description, tech, github, live) VALUES (?, ?, ?, ?, ?)'
  );
  

  // 2. Online Skill Development System
  insertProject.run(
    'Online Skill Development System',
    'Full-stack web application with dynamic pages, backed by a MySQL database.',
    'Java, JSP, Servlet, JDBC, MySQL',
    'https://github.com/shravani-ubale/skill-dev',
    '#'
  );
  
  // 3. Coffee Website System
  insertProject.run(
    'Coffee Website System',
    'Responsive website front end with Node.js server-side logic and Oracle DB.',
    'HTML, CSS, JavaScript, Node.js, Oracle',
    'https://github.com/shravani-ubale/coffee-website',
    '#'
  );

  // 4. Data Analytics Project
  insertProject.run(
    'Mobile Phone Usage Analysis',
    'Cleaned and analyzed student survey data using Pandas and built 10+ visualizations.',
    'Python, Pandas, Matplotlib, Seaborn, Plotly',
    'https://github.com/ubaleshravani87-bit/Healthcare-Data-Analysis', 
    '#'
  );
  
  console.log('✅ Default projects created');
}

// Seed admin user
const adminExists = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@portfolio.com');
if (!adminExists) {
  const hashed = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(
    'Shravani Ubale',
    'admin@portfolio.com',
    hashed
  );
  console.log('✅ Admin user created: admin@portfolio.com / admin123');
}

// ===== Helper: JWT =====
function generateToken(user) {
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ===== Middleware: Auth =====
function authenticate(req, res, next) {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token, access denied' });
  }

  const token = authHeader.split(' ')[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ============================================
// ROUTES
// ============================================

// Health check
app.get('/', (req, res) => {
  const users = db.prepare('SELECT COUNT(*) AS total FROM users').get().total;
  const messages = db.prepare('SELECT COUNT(*) AS total FROM messages').get().total;
  res.json({
    message: 'Backend running ✅',
    users,
    messages,
    endpoints: {
      register: 'POST /api/register',
      login: 'POST /api/login',
      me: 'GET /api/me (protected)',
      projects: 'GET /api/projects',
      contact: 'POST /api/contact'
    }
  });
});

// ===== Task 6: REGISTER =====
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be 6+ chars' });
    }

    const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
    if (existing) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const result = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(
      name.trim(),
      email.toLowerCase().trim(),
      hashedPassword
    );

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = generateToken(user);

    res.status(201).json({
      message: 'Account created',
      token,
      user: { id: user.id, name: user.name, email: user.email, joined: user.joined }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== Task 6: LOGIN =====
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = generateToken(user);

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, joined: user.joined }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== Task 6: PROTECTED ME =====
app.get('/api/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id, name, email, joined FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.json({ user });
});

// ===== Task 4/5: GET PROJECTS =====
app.get('/api/projects', (req, res) => {
  const projects = db.prepare('SELECT * FROM projects ORDER BY id DESC').all();
  res.json({ projects });
});

// ===== Task 4/5: CONTACT MESSAGE =====
app.post('/api/contact', (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: 'All fields required' });
    }

    db.prepare(
      'INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)'
    ).run(name.trim(), email.trim(), subject.trim(), message.trim());

    res.status(201).json({ message: 'Message sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📧 Login: admin@portfolio.com / admin123`);
});