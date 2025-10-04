const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Set this in your deployment environment
    ssl: process.env.PGSSLMODE ? { rejectUnauthorized: false } : false
});

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

app.use(express.static(__dirname));

// --- Database setup ---
async function setupDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS moods (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            mood TEXT NOT NULL,
            note TEXT,
            date DATE NOT NULL,
            time TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS friends (
            id SERIAL PRIMARY KEY,
            requester_id INTEGER NOT NULL REFERENCES users(id),
            addressee_id INTEGER NOT NULL REFERENCES users(id),
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            receiver_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
}
setupDb();

// --- Helper: Auth middleware ---
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// --- Helper: Check if two users are friends ---
async function areFriends(userId1, userId2) {
    const { rows } = await pool.query(
        `SELECT 1 FROM friends
         WHERE ((requester_id = $1 AND addressee_id = $2) OR (requester_id = $2 AND addressee_id = $1))
         AND status = 'accepted'`,
        [userId1, userId2]
    );
    return rows.length > 0;
}

// --- User Registration ---
app.post('/api/register', async (req, res) => {
    const { name, email, password, username } = req.body;
    if (!name || !email || !password || !username) return res.status(400).json({ error: 'Name, email, password, and username required' });
    const hash = bcrypt.hashSync(password, 10);
    try {
        const result = await pool.query(
            'INSERT INTO users (name, email, password, username) VALUES ($1, $2, $3, $4) RETURNING id',
            [name, email, hash, username]
        );
        req.session.userId = result.rows[0].id;
        res.json({ success: true, name });
    } catch (err) {
        res.status(400).json({ error: 'User already exists or username taken' });
    }
});

// --- User Login ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    res.json({ success: true, name: user.name });
});

// --- Get Current User Info ---
app.get('/api/user', requireLogin, async (req, res) => {
    const { rows } = await pool.query('SELECT id, name, email, username FROM users WHERE id = $1', [req.session.userId]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
});

// --- Save Mood ---
app.post('/api/mood', requireLogin, async (req, res) => {
    const { mood, note } = req.body;
    const now = new Date();
    const date = now.toISOString().slice(0, 10);
    const time = now.toTimeString().slice(0, 5);
    await pool.query(
        'INSERT INTO moods (user_id, mood, note, date, time) VALUES ($1, $2, $3, $4, $5)',
        [req.session.userId, mood, note, date, time]
    );
    res.json({ success: true });
});

// --- Get Mood History (weekly/monthly/custom) ---
app.get('/api/mood/history', requireLogin, async (req, res) => {
    const { type, from, to } = req.query;
    let sql = 'SELECT date, time, mood, note FROM moods WHERE user_id = $1';
    let params = [req.session.userId];
    if (from && to) {
        sql += ' AND date >= $2 AND date <= $3 ORDER BY date DESC, time DESC';
        params.push(from, to);
    } else if (type === 'week') {
        const dateLimit = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        sql += ' AND date >= $2 ORDER BY date DESC, time DESC';
        params.push(dateLimit);
    } else if (type === 'month') {
        const dateLimit = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        sql += ' AND date >= $2 ORDER BY date DESC, time DESC';
        params.push(dateLimit);
    } else {
        sql += ' ORDER BY date DESC, time DESC';
    }
    const { rows } = await pool.query(sql, params);
    res.json({ history: rows });
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
app.get('/api/users/search', requireLogin, async (req, res) => {
    const username = req.query.username;
    if (!username) return res.json({ users: [] });
    const { rows } = await pool.query(
        'SELECT id, name, username FROM users WHERE username ILIKE $1 AND id != $2',
        [`%${username}%`, req.session.userId]
    );
    res.json({ users: rows });
});

// --- Send Friend Request ---
app.post('/api/friends/request', requireLogin, async (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });
    try {
        await pool.query(
            `INSERT INTO friends (requester_id, addressee_id, status) VALUES ($1, $2, 'pending')`,
            [req.session.userId, userId]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: 'Request already sent or error' });
    }
});

// --- Get Friend Requests (received) ---
app.get('/api/friends/requests', requireLogin, async (req, res) => {
    const { rows } = await pool.query(
        `SELECT friends.id, users.name, users.username
         FROM friends
         JOIN users ON friends.requester_id = users.id
         WHERE friends.addressee_id = $1 AND friends.status = 'pending'`,
        [req.session.userId]
    );
    res.json({ requests: rows });
});

// --- Respond to Friend Request ---
app.post('/api/friends/respond', requireLogin, async (req, res) => {
    const { requestId, status } = req.body;
    if (!requestId || !['accepted', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid request' });
    await pool.query(
        `UPDATE friends SET status = $1 WHERE id = $2 AND addressee_id = $3`,
        [status, requestId, req.session.userId]
    );
    res.json({ success: true });
});

// --- List Friends ---
app.get('/api/friends/list', requireLogin, async (req, res) => {
    const { rows } = await pool.query(
        `SELECT u.id, u.name, u.username
         FROM users u
         WHERE u.id IN (
            SELECT CASE
                WHEN requester_id = $1 THEN addressee_id
                WHEN addressee_id = $1 THEN requester_id
            END
            FROM friends
            WHERE (requester_id = $1 OR addressee_id = $1) AND status = 'accepted'
         )`,
        [req.session.userId]
    );
    res.json({ friends: rows });
});

// --- Get Friend's Mood History ---
app.get('/api/friends/:friendId/mood/history', requireLogin, async (req, res) => {
    const friendId = parseInt(req.params.friendId, 10);
    if (!friendId) return res.status(400).json({ error: 'Friend ID required' });
    if (!(await areFriends(req.session.userId, friendId))) {
        return res.status(403).json({ error: 'Not friends' });
    }
    const { type, from, to } = req.query;
    let sql = 'SELECT date, time, mood, note FROM moods WHERE user_id = $1';
    let params = [friendId];
    if (from && to) {
        sql += ' AND date >= $2 AND date <= $3 ORDER BY date DESC, time DESC';
        params.push(from, to);
    } else if (type === 'week') {
        const dateLimit = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        sql += ' AND date >= $2 ORDER BY date DESC, time DESC';
        params.push(dateLimit);
    } else if (type === 'month') {
        const dateLimit = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
        sql += ' AND date >= $2 ORDER BY date DESC, time DESC';
        params.push(dateLimit);
    } else {
        sql += ' ORDER BY date DESC, time DESC';
    }
    const { rows } = await pool.query(sql, params);
    res.json({ history: rows });
});

// --- Send Message ---
app.post('/api/messages/send', requireLogin, async (req, res) => {
    const { receiverId, message } = req.body;
    if (!receiverId || !message) return res.status(400).json({ error: 'Receiver and message required' });
    if (!(await areFriends(req.session.userId, receiverId))) {
        return res.status(403).json({ error: 'Not friends' });
    }
    await pool.query(
        `INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1, $2, $3)`,
        [req.session.userId, receiverId, message]
    );
    res.json({ success: true });
});

// --- Get Messages with a Friend ---
app.get('/api/messages/:friendId', requireLogin, async (req, res) => {
    const friendId = parseInt(req.params.friendId, 10);
    if (!friendId) return res.status(400).json({ error: 'Friend ID required' });
    if (!(await areFriends(req.session.userId, friendId))) {
        return res.status(403).json({ error: 'Not friends' });
    }
    const { rows } = await pool.query(
        `SELECT id, sender_id, receiver_id, message, created_at
         FROM messages
         WHERE (sender_id = $1 AND receiver_id = $2)
            OR (sender_id = $2 AND receiver_id = $1)
         ORDER BY created_at ASC`,
        [req.session.userId, friendId]
    );
    res.json({ messages: rows });
});

// --- Delete Message ---
app.delete('/api/messages/:messageId', requireLogin, async (req, res) => {
    const messageId = parseInt(req.params.messageId, 10);
    if (!messageId) return res.status(400).json({ error: 'Message ID required' });
    const result = await pool.query(
        `DELETE FROM messages WHERE id = $1 AND sender_id = $2 RETURNING id`,
        [messageId, req.session.userId]
    );
    if (result.rowCount === 0) return res.status(403).json({ error: 'Not allowed' });
    res.json({ success: true });
});

// --- Serve frontend (optional, if you want to serve static files) ---
// app.use(express.static(path.join(__dirname)));

// --- Start server ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
