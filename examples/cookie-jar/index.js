import { createServer, startServer } from '#shared';
import { readFile } from 'fs/promises';
import crypto from 'crypto';

import db from './database.js';
import cookieParser from 'cookie-parser';

const app = createServer({ cookies: false });
const COOKIE_SECRET = 'FLASH -> this must never be stored in code, but in Secrets Manager';

const generateSessionId = () => crypto.randomBytes(16).toString('hex');

app.use(cookieParser(COOKIE_SECRET));

app.get('/', (req, res) => {
  if (!req.cookies) res.send('Cookies are disabled.');
  if (req.signedCookies.username) {
    res.redirect('/profile');
  } else {
    res.redirect('/login');
  }
});

app.get('/login', async (req, res) => {
  const loginPage = await readFile('./pages/login.html', 'utf-8');

  if (req.signedCookies.username) {
    res.redirect('/profile');
  }

  if (req.query.error) {
    res
      .status(403)
      .send(loginPage.replace('{{error}}', String(req.query.error)));
    return;
  }

  res.send(loginPage);
});

// Simulate user login and set a cookie
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await db.get(
    'SELECT * FROM users WHERE username = ? AND password = ?',
    [username, password]
  );

  if (user) {
    const sessionId = generateSessionId();
    await db.run('INSERT INTO sessions (id, username) VALUES (?, ?)', [sessionId, username]);
    res.cookie('sessionId', sessionId, {
      httpOnly: true /* FLASH -> makes the cookie inaccessible from JavaScript */,
      signed: true /* FLASH -> cookie still comes as plain text to the browser, but signed, therefore a modification
       on the client side will result in a different hash on the server - we know it was tinkered with */
    });
    res.redirect('/profile');
  } else {
    res.status(403).redirect('/login?error=Invalid login credentials.');
  }
});

app.post('/logout', (_, res) => {
  res.clearCookie('username');
  res.redirect('/login');
});

// Display user profile only if the username cookie exists
app.get('/profile', async (req, res) => {
  res.locals.title = 'Profile';

  const sessionId = req.signedCookies.sessionId;

  if (!sessionId) {
    return res.redirect('/login?error=Please login to view your profile.');
  }

  const session = await db.get('SELECT * FROM sessions WHERE id = ?', sessionId);

  if (session && session.username) {
    res.send(
      (await readFile('./pages/profile.html', 'utf-8')).replace(
        '{{username}}',
        session.username
      )
    );
  } else {
    return res.redirect('/login?error=Please login to view your profile.');
  }
});

startServer(app, { name: 'Cookie Jar' });
