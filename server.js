const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const dbPath = path.join(__dirname, 'moodtracker.db');
const db = new sqlite3.Database(dbPath);

app.use(cors({
    origin: 'http://localhost:3001', // Change to your frontend origin if needed
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'moodtracker_secret',
    resave: false,
    saveUninitialized: false
}));

// Serve static frontend files
app.use(express.static(__dirname));

// --- Database setup ---
db.serialize(() => {
    // Users table: stores user info
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // Moods table: stores mood entries per user
    db.run(`CREATE TABLE IF NOT EXISTS moods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mood TEXT NOT NULL,
        note TEXT,
        date TEXT NOT NULL,
        time TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Friends table: manages friend requests and accepted friends
    db.run(`CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_id INTEGER NOT NULL,
        addressee_id INTEGER NOT NULL,
        status TEXT NOT NULL, -- 'pending', 'accepted', 'rejected'
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(requester_id) REFERENCES users(id),
        FOREIGN KEY(addressee_id) REFERENCES users(id)
    )`);

    // Messages table: stores private messages between friends
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )`);
});

// --- Helper: Auth middleware ---
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// --- Helper: Check if two users are friends ---
function areFriends(userId1, userId2, cb) {
    db.get(
        `SELECT 1 FROM friends
         WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
         AND status = 'accepted'`,
        [userId1, userId2, userId2, userId1],
        (err, row) => cb(err, !!row)
    );
}

// --- User Registration ---
app.post('/api/register', (req, res) => {
    const { name, email, password, username } = req.body;
    if (!name || !email || !password || !username) return res.status(400).json({ error: 'Name, email, password, and username required' });
    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (name, email, password, username) VALUES (?, ?, ?, ?)', [name, email, hash, username], function(err) {
        if (err) return res.status(400).json({ error: 'User already exists or username taken' });
        req.session.userId = this.lastID;
        res.json({ success: true, name });
    });
});

// --- User Login ---
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        req.session.userId = user.id;
        res.json({ success: true, name: user.name });
    });
});

// --- Get Current User Info ---
app.get('/api/user', requireLogin, (req, res) => {
    db.get('SELECT id, name, email, username FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });
        res.json({ id: user.id, name: user.name, email: user.email, username: user.username });
    });
});

// --- Save Mood ---
app.post('/api/mood', requireLogin, (req, res) => {
    const { mood, note } = req.body;
    const now = new Date();
    const date = now.toISOString().slice(0, 10); // YYYY-MM-DD
    const time = now.toTimeString().slice(0, 5); // HH:MM (24hr)
    db.run('INSERT INTO moods (user_id, mood, note, date, time) VALUES (?, ?, ?, ?, ?)',
        [req.session.userId, mood, note, date, time],
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to save mood' });
            res.json({ success: true });
        }
    );
});

// --- Get Mood History (weekly/monthly/custom) ---
app.get('/api/mood/history', requireLogin, (req, res) => {
    const { type, from, to } = req.query;
    let sql = 'SELECT date, time, mood, note FROM moods WHERE user_id = ?';
    let params = [req.session.userId];

    if (from && to) {
        sql += ' AND date >= ? AND date <= ? ORDER BY date DESC, time DESC';
        params.push(from, to);
    } else if (type === 'week') {
        const dateLimit = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        sql += ' AND date >= ? ORDER BY date DESC, time DESC';
        params.push(dateLimit);
    } else if (type === 'month') {
        const dateLimit = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        sql += ' AND date >= ? ORDER BY date DESC, time DESC';
        params.push(dateLimit);
    } else {
        sql += ' ORDER BY date DESC, time DESC';
    }

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch history' });
        res.json({ history: rows });
    });
});

// --- Logout ---
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'LogIn.html'));
});

// --- User Search by Username ---
app.get('/api/users/search', requireLogin, (req, res) => {
    const username = req.query.username;
    if (!username) return res.json({ users: [] });
    db.all('SELECT id, name, username FROM users WHERE username LIKE ? AND id != ?', [`%${username}%`, req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ users: [] });
        res.json({ users: rows });
    });
});

// --- Send Friend Request ---
app.post('/api/friends/request', requireLogin, (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });
    db.run(
        `INSERT INTO friends (requester_id, addressee_id, status) VALUES (?, ?, 'pending')`,
        [req.session.userId, userId],
        function(err) {
            if (err) return res.status(400).json({ error: 'Request already sent or error' });
            res.json({ success: true });
        }
    );
});

// --- Get Friend Requests (received) ---
app.get('/api/friends/requests', requireLogin, (req, res) => {
    db.all(
        `SELECT friends.id, users.name, users.username
         FROM friends
         JOIN users ON friends.requester_id = users.id
         WHERE friends.addressee_id = ? AND friends.status = 'pending'`,
        [req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ requests: [] });
            res.json({ requests: rows });
        }
    );
});

// --- Respond to Friend Request ---
app.post('/api/friends/respond', requireLogin, (req, res) => {
    const { requestId, status } = req.body;
    if (!requestId || !['accepted', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid request' });
    db.run(
        `UPDATE friends SET status = ? WHERE id = ? AND addressee_id = ?`,
        [status, requestId, req.session.userId],
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to update request' });
            res.json({ success: true });
        }
    );
});

// --- List Friends ---
app.get('/api/friends/list', requireLogin, (req, res) => {
    db.all(
        `SELECT u.id, u.name, u.username
         FROM users u
         WHERE u.id IN (
            SELECT CASE
                WHEN requester_id = ? THEN addressee_id
                WHEN addressee_id = ? THEN requester_id
            END
            FROM friends
            WHERE (requester_id = ? OR addressee_id = ?) AND status = 'accepted'
         )`,
        [req.session.userId, req.session.userId, req.session.userId, req.session.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ friends: [] });
            res.json({ friends: rows });
        }
    );
});

// --- Get Friend's Mood History ---
app.get('/api/friends/:friendId/mood/history', requireLogin, (req, res) => {
    const friendId = parseInt(req.params.friendId, 10);
    if (!friendId) return res.status(400).json({ error: 'Friend ID required' });
    // Check if users are friends
    db.get(
        `SELECT 1 FROM friends
         WHERE ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
         AND status = 'accepted'`,
        [req.session.userId, friendId, friendId, req.session.userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            if (!row) return res.status(403).json({ error: 'Not friends' });
            // Fetch friend's moods (last 7 days by default, or by query)
            const { type, from, to } = req.query;
            let sql = 'SELECT date, time, mood, note FROM moods WHERE user_id = ?';
            let params = [friendId];
            if (from && to) {
                sql += ' AND date >= ? AND date <= ? ORDER BY date DESC, time DESC';
                params.push(from, to);
            } else if (type === 'week') {
                const dateLimit = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
                sql += ' AND date >= ? ORDER BY date DESC, time DESC';
                params.push(dateLimit);
            } else if (type === 'month') {
                const dateLimit = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
                sql += ' AND date >= ? ORDER BY date DESC, time DESC';
                params.push(dateLimit);
            } else {
                sql += ' ORDER BY date DESC, time DESC';
            }
            db.all(sql, params, (err2, rows) => {
                if (err2) return res.status(500).json({ error: 'Failed to fetch history' });
                res.json({ history: rows });
            });
        }
    );
});

// --- Send Message ---
app.post('/api/messages/send', requireLogin, (req, res) => {
    const { receiverId, message } = req.body;
    if (!receiverId || !message) return res.status(400).json({ error: 'Receiver and message required' });
    areFriends(req.session.userId, receiverId, (err, isFriend) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!isFriend) return res.status(403).json({ error: 'Not friends' });
        db.run(
            `INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)`,
            [req.session.userId, receiverId, message],
            function(err2) {
                if (err2) return res.status(500).json({ error: 'Failed to send message' });
                res.json({ success: true });
            }
        );
    });
});

// --- Get Messages with a Friend ---
app.get('/api/messages/:friendId', requireLogin, (req, res) => {
    const friendId = parseInt(req.params.friendId, 10);
    if (!friendId) return res.status(400).json({ error: 'Friend ID required' });
    areFriends(req.session.userId, friendId, (err, isFriend) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!isFriend) return res.status(403).json({ error: 'Not friends' });
        db.all(
            `SELECT id, sender_id, receiver_id, message, created_at
             FROM messages
             WHERE (sender_id = ? AND receiver_id = ?)
                OR (sender_id = ? AND receiver_id = ?)
             ORDER BY created_at ASC`,
            [req.session.userId, friendId, friendId, req.session.userId],
            (err2, rows) => {
                if (err2) return res.status(500).json({ error: 'Failed to fetch messages' });
                res.json({ messages: rows });
            }
        );
    });
});

// --- Delete Message ---
app.delete('/api/messages/:messageId', requireLogin, (req, res) => {
    const messageId = parseInt(req.params.messageId, 10);
    if (!messageId) return res.status(400).json({ error: 'Message ID required' });
    db.run(
        `DELETE FROM messages WHERE id = ? AND sender_id = ?`,
        [messageId, req.session.userId],
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to delete message' });
            if (this.changes === 0) return res.status(403).json({ error: 'Not allowed' });
            res.json({ success: true });
        }
    );
});

// --- Serve frontend (optional, if you want to serve static files) ---
// app.use(express.static(path.join(__dirname)));

// --- Start server ---
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
