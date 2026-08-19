/**
 * server.js
 * Secure remote-access signaling server.
 *
 * Responsibilities:
 *  - Google OAuth login (identifies the "host" account)
 *  - Generates unique, time-limited, one-time-use session links
 *  - Relays WebRTC signaling (offer/answer/ICE) between host <-> viewer
 *  - NEVER establishes a connection without explicit host approval
 *  - Rejects/expires stale or reused links
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.APP_BASE_URL, credentials: true }
});

const PORT = process.env.PORT || 3000;
const LINK_EXPIRY_MS = (parseInt(process.env.LINK_EXPIRY_MINUTES, 10) || 15) * 60 * 1000;

// ---------- Security middleware ----------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", "wss:", "https:"],
      imgSrc: ["'self'", "data:", "https://*.googleusercontent.com"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limit auth + link creation endpoints to slow brute force / abuse
const strictLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
app.use('/auth', strictLimiter);
app.use('/api/session', strictLimiter);

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,       // requires HTTPS in production
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8 // 8 hours
  }
});
app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// ---------- Google OAuth ----------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  // Only store the minimum needed to identify the account
  const user = {
    id: profile.id,
    name: profile.displayName,
    email: profile.emails?.[0]?.value,
    avatar: profile.photos?.[0]?.value
  };
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (req, res) => res.redirect('/dashboard.html')
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/login.html'));
});

app.get('/api/me', ensureAuthenticated, (req, res) => res.json(req.user));

// ---------- Session link management ----------
// In-memory store for demo purposes. Swap for Redis/Mongo in production
// so links survive restarts and work across multiple server instances.
const activeLinks = new Map(); // token -> { hostSocketId, hostUserId, createdAt, used }

app.post('/api/session/create', ensureAuthenticated, (req, res) => {
  const token = crypto.randomBytes(24).toString('base64url'); // unique, unguessable
  activeLinks.set(token, {
    hostUserId: req.user.id,
    hostSocketId: null,   // filled in once the host's dashboard socket connects
    createdAt: Date.now(),
    used: false
  });

  // Auto-expire the link
  setTimeout(() => {
    const link = activeLinks.get(token);
    if (link && !link.used) activeLinks.delete(token);
  }, LINK_EXPIRY_MS);

  const shareUrl = `${process.env.APP_BASE_URL}/viewer.html?token=${token}`;
  res.json({ token, shareUrl, expiresInMinutes: LINK_EXPIRY_MS / 60000 });
});

app.post('/api/session/revoke', ensureAuthenticated, (req, res) => {
  const { token } = req.body;
  const link = activeLinks.get(token);
  if (link && link.hostUserId === req.user.id) {
    activeLinks.delete(token);
    io.to(token).emit('session-revoked');
  }
  res.json({ ok: true });
});

// ---------- Socket.io signaling (share the express session) ----------
io.engine.use(sessionMiddleware);

io.use((socket, next) => {
  const req = socket.request;
  if (req.session && req.session.passport && req.session.passport.user) {
    socket.user = req.session.passport.user; // authenticated host
  }
  next(); // viewers are allowed unauthenticated; they only get in via a valid token
});

io.on('connection', (socket) => {

  // Host's dashboard registers itself as the owner of a token
  socket.on('host-register', ({ token }) => {
    const link = activeLinks.get(token);
    if (!link || !socket.user || link.hostUserId !== socket.user.id) {
      return socket.emit('error-message', 'Invalid or unauthorized link.');
    }
    link.hostSocketId = socket.id;
    socket.join(token);
    socket.data.hostToken = token;
  });

  // Viewer requests to join using the shared link's token
  socket.on('viewer-request-access', ({ token }) => {
    const link = activeLinks.get(token);
    if (!link) return socket.emit('error-message', 'This link is invalid or has expired.');
    if (link.used) return socket.emit('error-message', 'This link has already been used.');
    if (Date.now() - link.createdAt > LINK_EXPIRY_MS) {
      activeLinks.delete(token);
      return socket.emit('error-message', 'This link has expired.');
    }
    if (!link.hostSocketId) {
      return socket.emit('error-message', 'Host is not currently online.');
    }

    socket.join(token);
    socket.data.viewerToken = token;

    // Ask the host to explicitly approve — NEVER auto-connect
    io.to(link.hostSocketId).emit('access-request', {
      viewerSocketId: socket.id,
      token
    });
  });

  // Host approves or denies
  socket.on('host-respond', ({ token, viewerSocketId, approved }) => {
    const link = activeLinks.get(token);
    if (!link || link.hostSocketId !== socket.id) return;

    if (approved) {
      link.used = true; // one-time-use link
      io.to(viewerSocketId).emit('access-approved', { token });
    } else {
      io.to(viewerSocketId).emit('access-denied');
    }
  });

  // WebRTC signaling relay (offer/answer/ICE candidates) — server never
  // inspects or stores the media, it just passes messages between the pair
  socket.on('webrtc-signal', ({ token, targetSocketId, signal }) => {
    const link = activeLinks.get(token);
    if (!link) return;
    const isHost = socket.id === link.hostSocketId;
    const isViewerInRoom = socket.rooms.has(token);
    if (!isHost && !isViewerInRoom) return; // must belong to this session
    io.to(targetSocketId).emit('webrtc-signal', { signal, from: socket.id });
  });

  socket.on('end-session', ({ token }) => {
    io.to(token).emit('session-ended');
    activeLinks.delete(token);
  });

  socket.on('disconnect', () => {
    const token = socket.data.hostToken;
    if (token) {
      io.to(token).emit('session-ended');
      activeLinks.delete(token);
    }
  });
});

server.listen(PORT, () => {
  console.log(`Remote access server running on port ${PORT}`);
});
