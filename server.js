
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");
const db = require("./database");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "local-development-secret-change-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

app.post("/signup", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Username must be 3-20 letters, numbers or underscores."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password must be 8-72 characters."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    ).run(username, hash);

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Session creation failed." });
      }

      req.session.userId = result.lastInsertRowid;
      req.session.username = username;

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: "Session save failed." });
        }

        res.json({ message: "Signup successful!", username });
      });
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username already exists." });
    }

    console.error(error);
    res.status(500).json({ error: "Signup failed." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const user = db.prepare(
      "SELECT * FROM users WHERE username = ?"
    ).get(username);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Incorrect username or password."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: "Session creation failed." });
      }

      req.session.userId = user.id;
      req.session.username = user.username;

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: "Session save failed." });
        }

        res.json({ message: "Login successful!", username: user.username });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed." });
  }
});

app.get("/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please login." });
  }

  res.json({ username: req.session.username });
});

app.get("/users", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please login." });
  }

  const search = String(req.query.search || "").trim();

  if (search.length < 1 || search.length > 20) {
    return res.json({ users: [] });
  }

  const escapedSearch = search.replace(/[\\%_]/g, "\\$&");

  const users = db.prepare(`
    SELECT username
    FROM users
    WHERE username LIKE ? ESCAPE '\\'
      AND id != ?
    ORDER BY username
    LIMIT 20
  `).all("%" + escapedSearch + "%", req.session.userId);

  res.json({ users });
});

app.get("/messages", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please login." });
  }

  const otherUsername = String(req.query.with || "").trim();

  const otherUser = db.prepare(
    "SELECT id FROM users WHERE username = ?"
  ).get(otherUsername);

  if (!otherUser) {
    return res.status(404).json({ error: "User not found." });
  }

  const messages = db.prepare(`
    SELECT
      sender.username AS sender,
      receiver.username AS receiver,
      messages.message_text AS text,
      messages.created_at AS created_at
    FROM messages
    JOIN users AS sender ON sender.id = messages.sender_id
    JOIN users AS receiver ON receiver.id = messages.receiver_id
    WHERE
      (messages.sender_id = ? AND messages.receiver_id = ?)
      OR
      (messages.sender_id = ? AND messages.receiver_id = ?)
    ORDER BY messages.id ASC
    LIMIT 500
  `).all(
    req.session.userId, otherUser.id,
    otherUser.id, req.session.userId
  );

  res.json({
    messages: messages.map(m => ({
      from: m.sender,
      to: m.receiver,
      text: m.text,
      createdAt: m.created_at
    }))
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed." });
    }

    res.clearCookie("connect.sid");
    res.json({ message: "Logged out." });
  });
});

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

io.use((socket, next) => {
  if (socket.request.session?.userId) {
    return next();
  }

  next(new Error("Please login first."));
});

const onlineUsers = new Map();

io.on("connection", (socket) => {
  const userSession = socket.request.session;
  const username = userSession.username;

  if (!onlineUsers.has(username)) {
    onlineUsers.set(username, new Set());
  }

  onlineUsers.get(username).add(socket.id);
  console.log(username + " connected");

  socket.on("private message", (data) => {
    if (!data || typeof data !== "object") return;

    const to = String(data.to || "").trim();
    const text = String(data.text || "").trim().slice(0, 1000);

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(to) || !text) {
      socket.emit("private message error", "Invalid username or message.");
      return;
    }

    const recipient = db.prepare(
      "SELECT id FROM users WHERE username = ?"
    ).get(to);

    if (!recipient) {
      socket.emit("private message error", "User not found.");
      return;
    }

    const result = db.prepare(`
      INSERT INTO messages (sender_id, receiver_id, message_text)
      VALUES (?, ?, ?)
    `).run(userSession.userId, recipient.id, text);

    const message = {
      id: result.lastInsertRowid,
      from: username,
      to,
      text
    };

    const recipientSockets = onlineUsers.get(to);

    if (recipientSockets && recipientSockets.size > 0) {
      for (const socketId of recipientSockets) {
        io.to(socketId).emit("private message", message);
      }
    }

    socket.emit("private message sent", message);
  });

  socket.on("disconnect", () => {
    const sockets = onlineUsers.get(username);

    if (sockets) {
      sockets.delete(socket.id);

      if (sockets.size === 0) {
        onlineUsers.delete(username);
      }
    }

    console.log(username + " disconnected");
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Terminal Chat running on port ${PORT}`);
});
