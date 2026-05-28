const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const multer = require("multer");
const path = require("path");

const app = express();
const db = new sqlite3.Database("./database/app.db");

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

app.use(session({
  secret: "sky-secret",
  resave: false,
  saveUninitialized: false
}));

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      email TEXT UNIQUE,
      password TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      image_path TEXT,
      caption TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS exchanges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      my_post_id INTEGER,
      received_post_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
}

app.get("/", (req, res) => {
  res.redirect("/home");
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    [username, email, hash],
    function (err) {
      if (err) {
        return res.render("register", { error: "このメールアドレスは既に使われています" });
      }
      res.redirect("/login");
    }
  );
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) {
      return res.render("login", { error: "メールアドレスまたはパスワードが違います" });
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      return res.render("login", { error: "メールアドレスまたはパスワードが違います" });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect("/home");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

app.get("/home", requireLogin, (req, res) => {
  db.all(
    `SELECT posts.*, users.username
     FROM posts
     JOIN users ON posts.user_id = users.id
     ORDER BY posts.created_at DESC`,
    [],
    (err, posts) => {
      res.render("home", {
        username: req.session.username,
        posts
      });
    }
  );
});

app.get("/upload", requireLogin, (req, res) => {
  res.render("upload", { error: null });
});

app.post("/upload", requireLogin, upload.single("photo"), (req, res) => {
  const userId = req.session.userId;
  const caption = req.body.caption || "";

  db.get(
    "SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
    [userId],
    (err, lastPost) => {
      if (lastPost) {
        const lastTime = new Date(lastPost.created_at);
        const now = new Date();
        const diff = now - lastTime;

        if (diff < 24 * 60 * 60 * 1000) {
          return res.render("upload", {
            error: "投稿は24時間に1回だけです"
          });
        }
      }

      const imagePath = "/uploads/" + req.file.filename;

      db.run(
        "INSERT INTO posts (user_id, image_path, caption) VALUES (?, ?, ?)",
        [userId, imagePath, caption],
        function () {
          const myPostId = this.lastID;

          db.get(
            `SELECT * FROM posts
             WHERE user_id != ?
             ORDER BY RANDOM()
             LIMIT 1`,
            [userId],
            (err, receivedPost) => {
              if (!receivedPost) {
                return res.redirect("/exchange?none=1");
              }

              db.run(
                "INSERT INTO exchanges (user_id, my_post_id, received_post_id) VALUES (?, ?, ?)",
                [userId, myPostId, receivedPost.id],
                () => {
                  res.redirect("/exchange");
                }
              );
            }
          );
        }
      );
    }
  );
});

app.get("/exchange", requireLogin, (req, res) => {
  if (req.query.none) {
    return res.render("exchange", { post: null });
  }

  db.get(
    `SELECT posts.*, users.username
     FROM exchanges
     JOIN posts ON exchanges.received_post_id = posts.id
     JOIN users ON posts.user_id = users.id
     WHERE exchanges.user_id = ?
     ORDER BY exchanges.created_at DESC
     LIMIT 1`,
    [req.session.userId],
    (err, post) => {
      res.render("exchange", { post });
    }
  );
});

app.get("/mypage", requireLogin, (req, res) => {
  db.all(
    "SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC",
    [req.session.userId],
    (err, myPosts) => {
      db.all(
        `SELECT posts.*, users.username
         FROM exchanges
         JOIN posts ON exchanges.received_post_id = posts.id
         JOIN users ON posts.user_id = users.id
         WHERE exchanges.user_id = ?
         ORDER BY exchanges.created_at DESC`,
        [req.session.userId],
        (err, receivedPosts) => {
          res.render("mypage", {
            username: req.session.username,
            myPosts,
            receivedPosts
          });
        }
      );
    }
  );
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`SkySwap running on port ${PORT}`);
});