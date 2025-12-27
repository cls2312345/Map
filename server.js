const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const useragent = require('express-useragent');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const BAD_WORDS = ['fuck', 'shit', 'nigger', 'nazi', 'porn', 'cunt', 'dick', 'pussy'];

function writeLog(msg) {
    const timestamp = new Date().toLocaleString();
    const logMsg = `[${timestamp}] ${msg}\n`;
    fs.appendFileSync('server.log', logMsg);
    console.log(logMsg.trim());
}

let db;
(async () => {
    db = await open({ filename: './database.db', driver: sqlite3.Database });
    await db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)`);
    await db.exec(`CREATE TABLE IF NOT EXISTS bans (username TEXT UNIQUE)`);
    writeLog("SYSTEM: Database and Admin System Started.");
})();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(useragent.express());
app.use(session({ secret: 'collin-super-secret-key', resave: false, saveUninitialized: false }));
app.use(express.static(__dirname));

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hasBadWord = BAD_WORDS.some(word => username.toLowerCase().includes(word));
    if (hasBadWord) {
        await db.run('INSERT OR IGNORE INTO bans (username) VALUES (?)', [username]);
        writeLog(`AUTO-BAN: ${username} attempted registration.`);
        return res.status(403).send("<h2>Auto-banned for profanity.</h2><a href='/'>Back</a>");
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        writeLog(`USER: ${username} registered.`);
        res.send("<h2>Account created!</h2><a href='/'>Login</a>");
    } catch (e) { res.status(400).send("Username exists."); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const isBanned = await db.get('SELECT * FROM bans WHERE username = ?', [username]);
    if (isBanned) return res.send("<h2>Banned.</h2>");
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user.id;
        req.session.username = user.username;
        writeLog(`LOGIN: ${username} connected.`);
        res.redirect('/map');
    } else { res.send("Invalid login."); }
});

app.get('/map', (req, res) => {
    if (!req.session.userId) return res.redirect('/');
    let content = fs.readFileSync(path.join(__dirname, 'map.html'), 'utf8');
    const device = req.useragent.isMobile ? "Mobile 📱" : "PC 💻";
    content = content.replace('USER_NAME_PLACEHOLDER', req.session.username)
                     .replace('IS_OWNER_PLACEHOLDER', req.session.username.toLowerCase() === 'collin')
                     .replace('DEVICE_TYPE_PLACEHOLDER', device);
    res.send(content);
});

const activeUsers = {};
const hiddenUsers = new Set();

io.on('connection', (socket) => {
    const userIP = socket.handshake.address.replace('::ffff:', '');
    socket.on('send-location', (data) => {
        const status = hiddenUsers.has(data.name) ? "Hidden 🔒" : "Active 🟢";
        activeUsers[socket.id] = { ...data, status, ip: userIP, lastSeen: new Date().toLocaleTimeString() };
        io.emit('update-data', { users: activeUsers, hiddenList: Array.from(hiddenUsers) });
    });
    socket.on('send-chat', (msg) => {
        writeLog(`CHAT: ${msg.name}: ${msg.text}`);
        io.emit('receive-chat', msg);
    });
    socket.on('owner-ban-user', async (n) => {
        if (n.toLowerCase() === 'collin') return;
        await db.run('INSERT OR IGNORE INTO bans (username) VALUES (?)', [n]);
        io.emit('ban-notice', n);
    });
    socket.on('owner-unban-user', async (n) => { await db.run('DELETE FROM bans WHERE username = ?', [n]); });
    socket.on('owner-hide-user', (n) => { hiddenUsers.add(n); io.emit('update-data', { users: activeUsers, hiddenList: Array.from(hiddenUsers) }); });
    socket.on('owner-show-user', (n) => { hiddenUsers.delete(n); io.emit('update-data', { users: activeUsers, hiddenList: Array.from(hiddenUsers) }); });
    socket.on('owner-broadcast', (m) => io.emit('server-msg', m));
    socket.on('disconnect', () => { delete activeUsers[socket.id]; io.emit('user-left', socket.id); });
});
server.listen(3000, () => writeLog("SYSTEM: Running on port 3000"));