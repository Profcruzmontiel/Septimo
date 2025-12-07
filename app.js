// app.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const methodOverride = require('method-override');
const helmet = require('helmet');
const csurf = require('csurf');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const db = new sqlite3.Database('./data/app.db');

// Configuración de vistas y layouts
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout'); // archivo layout.ejs en /views

// Middlewares de seguridad y utilidades
app.use(helmet());
app.use(express.urlencoded({ extended: true })); // formularios POST
app.use(express.json()); // JSON API
app.use(methodOverride('_method')); // soporta PUT/DELETE desde formularios
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret', // ⚠️ usar variable de entorno en producción
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));
app.use(csurf());

// Middleware de usuario
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Utilidad para proteger rutas
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// Rutas públicas
app.get('/', (req, res) => {
  res.render('index', { title: 'Inicio' });
});

// Registro
app.get('/register', (req, res) => {
  res.render('register', { title: 'Registro' });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('register', { title: 'Registro', error: 'Completa todos los campos.' });
  }
  const hash = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
    [username, hash],
    function (err) {
      if (err) {
        return res.render('register', { title: 'Registro', error: 'Usuario ya existe o error.' });
      }
      req.session.user = { id: this.lastID, username };
      res.redirect('/dashboard');
    }
  );
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.render('login', { title: 'Login', error: 'Credenciales inválidas.' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.render('login', { title: 'Login', error: 'Credenciales inválidas.' });
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/dashboard');
  });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Dashboard
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { title: 'Panel' });
});

// CRUD Items
app.get('/items', requireAuth, (req, res) => {
  db.all('SELECT * FROM items WHERE owner_id = ? ORDER BY created_at DESC', [req.session.user.id], (err, rows) => {
    res.render('items/list', { title: 'Mis elementos', items: rows || [] });
  });
});

app.get('/items/new', requireAuth, (req, res) => {
  res.render('items/new', { title: 'Nuevo elemento' });
});

app.post('/items', requireAuth, (req, res) => {
  const { title, description } = req.body;
  db.run(
    'INSERT INTO items (title, description, owner_id) VALUES (?, ?, ?)',
    [title, description || '', req.session.user.id],
    (err) => {
      if (err) return res.render('items/new', { title: 'Nuevo elemento', error: 'Error al crear.' });
      res.redirect('/items');
    }
  );
});

app.get('/items/:id/edit', requireAuth, (req, res) => {
  db.get('SELECT * FROM items WHERE id = ? AND owner_id = ?', [req.params.id, req.session.user.id], (err, item) => {
    if (!item) return res.redirect('/items');
    res.render('items/edit', { title: 'Editar elemento', item });
  });
});

app.put('/items/:id', requireAuth, (req, res) => {
  const { title, description } = req.body;
  db.run(
    'UPDATE items SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND owner_id = ?',
    [title, description, req.params.id, req.session.user.id],
    (err) => {
      res.redirect('/items');
    }
  );
});

app.delete('/items/:id', requireAuth, (req, res) => {
  db.run('DELETE FROM items WHERE id = ? AND owner_id = ?', [req.params.id, req.session.user.id], (err) => {
    res.redirect('/items');
  });
});

// API JSON
app.get('/api/items', requireAuth, (req, res) => {
  db.all('SELECT id, title, description FROM items WHERE owner_id = ?', [req.session.user.id], (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/items', requireAuth, (req, res) => {
  const { title, description } = req.body;
  db.run(
    'INSERT INTO items (title, description, owner_id) VALUES (?, ?, ?)',
    [title, description || '', req.session.user.id],
    function (err) {
      if (err) return res.status(400).json({ error: 'Error al crear' });
      res.status(201).json({ id: this.lastID, title, description });
    }
  );
});

// Servidor
const PORT = process.env.PORT || 3000; // ⚠️ usar puerto dinámico en hosting
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));