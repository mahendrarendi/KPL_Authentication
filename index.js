const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const mysql = require('mysql2/promise');
const winston = require('winston');
const moment = require('moment');
const crypto = require('crypto'); // Tambahkan ini
const cookieParser = require('cookie-parser'); // Tambahkan ini

require('dotenv').config();

const app = express();
app.use(cookieParser()); // Gunakan middleware cookie-parser

// Konfigurasi Database
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Konfigurasi logger
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.printf(({ level, message, timestamp }) => {
      return `${level}: ${message} pada ${moment(timestamp).format('YYYY-MM-DD HH:mm:ss')}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'activity.log' }),
  ],
});

// Middleware
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

app.use((req, res, next) => {
  req.session.failedAttempts = req.session.failedAttempts || 0;
  next();
});

// Routing
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  // Cek peran pengguna dan arahkan sesuai peran
  if (req.session.role === 'Admin') {
    res.render('admin');
  } else if (req.session.role === 'Dosen') {
    res.render('dosen');
  } else if (req.session.role === 'Mahasiswa') {
    res.render('index', { user: req.session.user });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { message: req.session.message });
  req.session.message = null; // Clear the message after rendering
});

app.post('/login', async (req, res) => {
  const { emailOrUsername, password, remember_me } = req.body;

  try {
    const connection = await pool.getConnection();
    let [rows] = [];

    if (emailOrUsername && typeof emailOrUsername === 'string') {
      if (emailOrUsername.includes('@')) {
        [rows] = await connection.execute('SELECT * FROM Users WHERE email = ?', [emailOrUsername]);
      } else {
        [rows] = await connection.execute('SELECT * FROM Users WHERE username = ?', [emailOrUsername]);
      }
    } else {
      req.session.message = 'Invalid email or username';
      return res.redirect('/login');
    }

    connection.release();

    if (rows.length > 0) {
      const user = rows[0];
      if (bcrypt.compareSync(password, user.password)) {
        req.session.failedAttempts = 0;
        req.session.user = user;
        req.session.role = user.role;

        logger.info(`Pengguna ${user.username} berhasil masuk sebagai ${user.role}`);

        // Jika "Remember Me" dicentang, set cookie remember_token
        if (remember_me) {
          const rememberToken = generateRememberToken();
          await storeRememberToken(user.id, rememberToken);

          // Set cookie dengan remember token (atur waktu kadaluwarsa sesuai kebutuhan Anda)
          res.cookie('remember_token', rememberToken, { maxAge: 30 * 24 * 60 * 60 * 1000 }); // 30 hari
        }

        // Redirect sesuai peran pengguna
        if (req.session.role === 'Admin') {
          res.redirect('/admin');
        } else if (req.session.role === 'Dosen') {
          res.redirect('/dosen');
        } else if (req.session.role === 'Mahasiswa') {
          res.redirect('/');
        }
      } else {
        req.session.failedAttempts = (req.session.failedAttempts || 0) + 1;
        if (req.session.failedAttempts >= 3) {
          if (req.session.lockedUntil && req.session.lockedUntil > Date.now()) {
            const remainingTime = Math.ceil((req.session.lockedUntil - Date.now()) / 1000);
            return res.status(403).send(`You are locked out. Please try again in ${remainingTime} seconds.`);
          } else {
            req.session.lockedUntil = Date.now() + 5 * 60 * 1000; // Kunci pengguna selama 5 menit
          }
        }

        logger.error(`Gagal masuk untuk pengguna dengan nama ${emailOrUsername}`);
        req.session.message = 'Invalid email or password';
        res.redirect('/login');
      }
    } else {
      req.session.message = 'Invalid email or password';
      res.redirect('/login');
    }
  } catch (error) {
    console.error(error);
    console.log('Input emailOrUsername:', emailOrUsername);
    res.status(500).send('Internal server error');
  }
});

// Middleware untuk menangani pemblokiran
app.use((req, res, next) => {
  if (req.session.lockedUntil && req.session.lockedUntil > Date.now()) {
    const remainingTime = Math.ceil((req.session.lockedUntil - Date.now()) / 1000);
    req.session.message = `You are locked out. Please try again in ${remainingTime} seconds.`;

    if (req.session.user === null || req.session.user === undefined) {
      return res.redirect('/login');
    } else {
      setTimeout(() => {
        delete req.session.lockedUntil;
      }, 5 * 60 * 1000); // Hapus lockedUntil setelah 5 menit
    }
  }

  next();
});

app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    const connection = await pool.getConnection();
    await connection.execute('INSERT INTO Users (username, email, password, role, createdAt, updatedAt) VALUES (?, ?, ?, ?, NOW(), NOW())', [username, email, hashedPassword, role]);
    connection.release();

    logger.info(`Pengguna ${username} berhasil register dengan peran ${role}`);

    res.redirect('/login');
  } catch (error) {
    console.error(error);
    req.session.message = 'Failed to register user';

    logger.error(`Gagal register untuk pengguna dengan nama ${username}`);

    res.redirect('/register');
  }
});

app.get('/register', (req, res) => {
  res.render('register', { message: req.session.message });
  req.session.message = null;
});

app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.role !== 'Admin') {
    return res.status(403).send('Access denied');
  }
  res.render('admin', { user: req.session.user });
});

app.get('/dosen', (req, res) => {
  if (!req.session.user || req.session.role !== 'Dosen') {
    return res.status(403).send('Access denied');
  }
  res.render('dosen', { user: req.session.user });
});

// Generate random remember token
function generateRememberToken() {
  return crypto.randomBytes(40).toString('hex');
}

// Store remember token in the database
async function storeRememberToken(userId, rememberToken) {
  try {
    const connection = await pool.getConnection();
    await connection.execute('UPDATE Users SET remember_token = ? WHERE id = ?', [rememberToken, userId]);
    connection.release();
  } catch (error) {
    console.error(error);
    // Tangani kesalahan dengan benar
  }
}

app.get('/logout', (req, res) => {
  if (req.cookies.remember_token) {
    // Hapus cookie remember_token
    res.clearCookie('remember_token');
  }

  if (req.session.user) {
    const { username, role } = req.session.user;
    logger.info(`Pengguna ${username} berhasil logout dari peran ${role}`);
  }

  req.session.message = {
    type: 'logout',
    text: 'You have successfully logged out.',
  };

  const logoutMessage = req.session.message;

  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }

    res.redirect(`/login?message=${JSON.stringify(logoutMessage)}`);
  });
});

app.listen(3000, () => {
  console.log('Server berjalan pada port 3000');
});
