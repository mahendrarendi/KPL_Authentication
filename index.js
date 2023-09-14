const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const mysql = require('mysql2/promise');
const winston = require('winston');
const moment = require('moment');
require('dotenv').config();

const app = express();

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
    res.render('admin'); // Halaman admin
  } else if (req.session.role === 'Dosen') {
    res.render('dosen'); // Halaman dosen
  } else if (req.session.role === 'Mahasiswa') {
    res.render('index', { user: req.session.user }); // Halaman mahasiswa dengan variabel user
  }
});


app.get('/login', (req, res) => {
  res.render('login', { message: req.session.message });
  req.session.message = null; // Clear the message after rendering
});


app.post('/login', async (req, res) => {
  const { emailOrUsername, password } = req.body; // Ganti "username" menjadi "emailOrUsername"

  try {
    const connection = await pool.getConnection();
    let [rows] = [];

    // Periksa apakah input adalah email atau username
    if (emailOrUsername && typeof emailOrUsername === 'string') {
      if (emailOrUsername.includes('@')) {
        // Input adalah email
        [rows] = await connection.execute('SELECT * FROM Users WHERE email = ?', [emailOrUsername]);
      } else {
        // Input adalah username
        [rows] = await connection.execute('SELECT * FROM Users WHERE username = ?', [emailOrUsername]);
      }
    } else {
      // Input tidak valid, atasi dengan memberikan pesan kesalahan
      req.session.message = 'Invalid email or username';
      return res.redirect('/login');
    }

    connection.release();

    if (rows.length > 0) {
      const user = rows[0];
      if (bcrypt.compareSync(password, user.password)) {
        // Reset failed login attempts setelah berhasil login
        req.session.failedAttempts = 0;

        // Set user info in session
        req.session.user = user;

        // Set user role in session
        req.session.role = user.role; // Ambil peran dari basis data

        // Log aktivitas masuk yang berhasil
        logger.info(`Pengguna ${user.username} berhasil masuk sebagai ${user.role}`);

        // Berdasarkan peran pengguna, arahkan ke rute yang sesuai
        if (req.session.role === 'Admin') {
          res.redirect('/admin'); // Redirect ke halaman admin
        } else if (req.session.role === 'Dosen') {
          res.redirect('/dosen'); // Redirect ke halaman dosen
        } else if (req.session.role === 'Mahasiswa') {
          res.redirect('/'); // Redirect ke halaman utama
        }
      } else {
        // Increment failed login attempts
        req.session.failedAttempts = (req.session.failedAttempts || 0) + 1;

        // Check for lockout after 3 failed attempts
        if (req.session.failedAttempts >= 3) {
          if (req.session.lockedUntil && req.session.lockedUntil > Date.now()) {
            const remainingTime = Math.ceil((req.session.lockedUntil - Date.now()) / 1000);
            return res.status(403).send(`You are locked out. Please try again in ${remainingTime} seconds.`);
          } else {
            req.session.lockedUntil = Date.now() + 1 * 60 * 1000; // Lock user for 5 minutes
          }
        }

        // Log aktivitas masuk yang gagal
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
  // Check if user is locked out
  if (req.session.lockedUntil && req.session.lockedUntil > Date.now()) {
    const remainingTime = Math.ceil((req.session.lockedUntil - Date.now()) / 1000);
    req.session.message = `You are locked out. Please try again in ${remainingTime} seconds.`;

    // Jika pengguna mencoba mengakses halaman lain selain /login
    if (req.session.user === null || req.session.user === undefined) {
      return res.redirect('/login');
    } else {
      // Menghapus req.session.lockedUntil setelah waktu tertentu
      setTimeout(() => {
        delete req.session.lockedUntil;
      }, 5 * 60 * 1000); // Menghapus lockedUntil setelah 5 menit
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

      // Log aktivitas register yang berhasil
      logger.info(`Pengguna ${username} berhasil register dengan peran ${role}`);
  
      res.redirect('/login');
    } catch (error) {
      console.error(error);
      req.session.message = 'Failed to register user'; // Set error message

      // Log aktivitas gagal register
      logger.error(`Gagal register untuk pengguna dengan nama ${username}`);

      res.redirect('/register'); // Redirect back to the register page
    }
  });
  
  app.get('/register', (req, res) => {
    res.render('register', { message: req.session.message }); // Send the message to the register view
    req.session.message = null; // Clear the message after rendering
  });

  app.get('/admin', (req, res) => {
    if (!req.session.user || req.session.role !== 'Admin') {
      return res.status(403).send('Access denied'); // Mengizinkan hanya pengguna dengan peran Admin
    }
    res.render('admin', { user: req.session.user }); // Anda perlu melewatkan user ke template EJS
  });

  app.get('/dosen', (req, res) => {
    if (!req.session.user || req.session.role !== 'Dosen') {
      return res.status(403).send('Access denied'); // Mengizinkan hanya pengguna dengan peran Admin
    }
    res.render('dosen', { user: req.session.user }); // Anda perlu melewatkan user ke template EJS
  });
  
  
  
  // Rute logout
  app.get('/logout', (req, res) => {
    if (req.session.user) {
      const { username, role } = req.session.user;
      // Log aktivitas logout yang berhasil
      logger.info(`Pengguna ${username} berhasil logout dari peran ${role}`);
    }

    req.session.destroy((err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/login');
    });
  });
  
app.listen(3000, () => {
  console.log('Server berjalan pada port 3000');
});