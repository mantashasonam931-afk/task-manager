const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'change-this-secret';
const db = new DatabaseSync(path.join(__dirname, 'tasks.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user');
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT NOT NULL, description TEXT DEFAULT '',
  priority TEXT DEFAULT 'medium', status TEXT DEFAULT 'todo', due_date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try { req.user = jwt.verify(h.replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in' }); }
}

// ---- Auth ----
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Name, email and password (min 6 chars) required' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email))
    return res.status(409).json({ error: 'Email already registered' });
  const first = db.prepare('SELECT COUNT(*) c FROM users').get().c === 0;   // first user = admin
  const info = db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)')
    .run(name, email, bcrypt.hashSync(password, 10), first ? 'admin' : 'user');
  const u = { id: info.lastInsertRowid, name, role: first ? 'admin' : 'user' };
  res.json({ token: sign(u), user: u });
});

app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(req.body.email || '');
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password))
    return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role } });
});

// ---- Tasks (CRUD) ----
// users see only their own tasks; admin sees everyone's
app.get('/api/tasks', auth, (req, res) => {
  const sql = `SELECT t.*, u.name owner FROM tasks t JOIN users u ON u.id=t.user_id
    ${req.user.role === 'admin' ? '' : 'WHERE t.user_id=?'} ORDER BY t.id DESC`;
  res.json(req.user.role === 'admin' ? db.prepare(sql).all() : db.prepare(sql).all(req.user.id));
});

app.post('/api/tasks', auth, (req, res) => {
  const { title, description, priority, status, due_date } = req.body;
  if (!title || !title.trim()) return res.status(400).json({ error: 'Title is required' });
  const info = db.prepare('INSERT INTO tasks(user_id,title,description,priority,status,due_date) VALUES(?,?,?,?,?,?)')
    .run(req.user.id, title.trim(), description || '', priority || 'medium', status || 'todo', due_date || null);
  res.json(db.prepare('SELECT * FROM tasks WHERE id=?').get(info.lastInsertRowid));
});

function owned(req, res, next) {
  const t = db.prepare('SELECT * FROM tasks WHERE id=?').get(req.params.id);
  if (!t) return res.status(404).json({ error: 'Task not found' });
  if (t.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not allowed' });
  req.task = t; next();
}

app.put('/api/tasks/:id', auth, owned, (req, res) => {
  const t = { ...req.task, ...req.body };
  db.prepare('UPDATE tasks SET title=?,description=?,priority=?,status=?,due_date=? WHERE id=?')
    .run(t.title, t.description, t.priority, t.status, t.due_date, t.id);
  res.json(db.prepare('SELECT * FROM tasks WHERE id=?').get(t.id));
});

app.delete('/api/tasks/:id', auth, owned, (req, res) => {
  db.prepare('DELETE FROM tasks WHERE id=?').run(req.task.id);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Task Manager running at http://localhost:${PORT}`));
