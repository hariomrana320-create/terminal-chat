const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const path = require("path");
const { db, initDatabase } = require("./database-pg");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.set("trust proxy", 1);
app.use(express.json());

const sessionMiddleware = session({
  store: new PgSession({
    pool: db,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "local-development-secret-change-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
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

    const result = await db.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
      [username, hash]
    );

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Session creation failed." });
      }

      req.session.userId = result.rows[0].id;
      req.session.username = username;

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error(saveErr);
          return res.status(500).json({ error: "Session save failed." });
        }

        res.json({ message: "Signup successful!", username });
      });
    });
  } catch (error) {
    if (error.code === "23505") {
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

    const result = await db.query(
      "SELECT id, username, password_hash FROM users WHERE username = $1",
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Incorrect username or password."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Session creation failed." });
      }

      req.session.userId = user.id;
      req.session.username = user.username;

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error(saveErr);
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

app.get("/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Please login." });
    }

    const result = await db.query(
      "SELECT username, avatar_id FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows[0]) {
      return res.status(401).json({ error: "Please login again." });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Profile load error:", error);
    res.status(500).json({ error: "Could not load profile." });
  }
});

app.post("/profile/avatar", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Please login." });
    }

    const avatarId = String(req.body.avatarId || "");

    if (!/^avatar-(0[1-9]|1[0-5])$/.test(avatarId)) {
      return res.status(400).json({ error: "Invalid avatar selection." });
    }

    await db.query(
      "UPDATE users SET avatar_id = $1 WHERE id = $2",
      [avatarId, req.session.userId]
    );

    res.json({ message: "Profile picture saved.", avatarId });
  } catch (error) {
    console.error("Avatar update error:", error);
    res.status(500).json({ error: "Could not save profile picture." });
  }
});

app.get("/users", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Please login." });
    }

    const search = String(req.query.search || "").trim();

    if (search.length < 1 || search.length > 20) {
      return res.json({ users: [] });
    }

    const result = await db.query(
      `SELECT username, avatar_id
       FROM users
       WHERE username ILIKE $1 AND id <> $2
       ORDER BY username
       LIMIT 20`,
      [`%${search}%`, req.session.userId]
    );

    res.json({ users: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "User search failed." });
  }
});

app.get("/messages", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Please login." });
    }

    const otherUsername = String(req.query.with || "").trim();

    const userResult = await db.query(
      "SELECT id FROM users WHERE username = $1",
      [otherUsername]
    );

    const otherUser = userResult.rows[0];

    if (!otherUser) {
      return res.status(404).json({ error: "User not found." });
    }

    const result = await db.query(
      `SELECT
         sender.username AS sender,
         receiver.username AS receiver,
         messages.message_text AS text,
         messages.created_at AS created_at
       FROM messages
       JOIN users AS sender ON sender.id = messages.sender_id
       JOIN users AS receiver ON receiver.id = messages.receiver_id
       WHERE
         (messages.sender_id = $1 AND messages.receiver_id = $2)
         OR
         (messages.sender_id = $2 AND messages.receiver_id = $1)
       ORDER BY messages.id ASC
       LIMIT 500`,
      [req.session.userId, otherUser.id]
    );

    res.json({
      messages: result.rows.map((m) => ({
        from: m.sender,
        to: m.receiver,
        text: m.text,
        createdAt: m.created_at
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load messages." });
  }
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

  socket.on("private message", async (data) => {
    try {
      if (!data || typeof data !== "object") return;

      const to = String(data.to || "").trim();
      const text = String(data.text || "").trim().slice(0, 1000);

      if (!/^[a-zA-Z0-9_]{3,20}$/.test(to) || !text) {
        socket.emit("private message error", "Invalid username or message.");
        return;
      }

      const recipientResult = await db.query(
        "SELECT id FROM users WHERE username = $1",
        [to]
      );

      const recipient = recipientResult.rows[0];

      if (!recipient) {
        socket.emit("private message error", "User not found.");
        return;
      }

      const saved = await db.query(
        `INSERT INTO messages (sender_id, receiver_id, message_text)
         VALUES ($1, $2, $3)
         RETURNING id, created_at`,
        [userSession.userId, recipient.id, text]
      );

      const message = {
        id: saved.rows[0].id,
        from: username,
        to,
        text,
        createdAt: saved.rows[0].created_at
      };

      const recipientSockets = onlineUsers.get(to);

      if (recipientSockets) {
        for (const socketId of recipientSockets) {
          io.to(socketId).emit("private message", message);
        }
      }

      socket.emit("private message sent", message);
    } catch (error) {
      console.error("Private message error:", error);
      socket.emit("private message error", "Message could not be sent.");
    }
  });

  function relayCallSignal(incomingEvent, outgoingEvent, field) {
    socket.on(incomingEvent, (data) => {
      if (!data || typeof data !== "object") return;

      const to = String(data.to || "").trim();
      const callId = String(data.callId || "").slice(0, 100);

      if (!/^[a-zA-Z0-9_]{3,20}$/.test(to) || !callId) return;

      const recipientSockets = onlineUsers.get(to);

      if (!recipientSockets || recipientSockets.size === 0) {
        socket.emit("call:unavailable", { to, callId });
        return;
      }

      const payload = { from: username, callId };

      if (field) {
        if (!data[field] || typeof data[field] !== "object") return;
        payload[field] = data[field];
      }

      for (const socketId of recipientSockets) {
        io.to(socketId).emit(outgoingEvent, payload);
      }
    });
  }

  relayCallSignal("call:offer", "call:offer", "offer");
  relayCallSignal("call:answer", "call:answer", "answer");
  relayCallSignal("call:ice-candidate", "call:ice-candidate", "candidate");
  relayCallSignal("call:end", "call:end", null);
  relayCallSignal("call:reject", "call:reject", null);

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

initDatabase()
  .then(() => {
    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Terminal Chat running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
