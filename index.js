import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import session from "express-session";
import { Strategy } from "passport-local";
import bcrypt from "bcrypt";
import passport from "passport";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 3;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  }),
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

db.connect();

app.get("/", async (req, res) => {
  res.render("home.ejs");
});

app.get("/new", async (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/books");
  } else {
    res.redirect("/login");
  }
});

app.post("/new", async (req, res) => {
  if (req.isAuthenticated()) {
    const title = req.body.bookname;
    const opinion = req.body.opinion;
    const data = new Date();
    const ano = data.getFullYear();
    const mes = String(data.getMonth() + 1).padStart(2, "0");
    const dia = String(data.getDate()).padStart(2, "0");
    const date = ano + " " + mes + " " + dia;
    const userId = req.user.id;
    try {
      await db.query(
        "INSERT INTO books (title, date, review, user_id) VALUES ($1, $2, $3, $4)",
        [title, date, opinion, userId],
      );
      res.redirect("/books");
    } catch (error) {
      console.log(error);
      res.redirect("/books");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/update", async (req, res) => {
  const idBook = req.body.updateBookId;
  const newOpinion = req.body.updateBookOpinion;

  if (req.isAuthenticated()) {
    try {
      await db.query("UPDATE books SET review = $1 WHERE id = $2", [
        newOpinion,
        idBook,
      ]);
      res.redirect("/books");
    } catch (error) {
      console.log(error);
      res.redirect("/books");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/delete", async (req, res) => {
  const idBook = req.body.id;
  if (req.isAuthenticated()) {
    try {
      await db.query("DELETE FROM books WHERE id = $1", [idBook]);
      res.redirect("/books");
    } catch (error) {
      console.log(error);
      res.redirect("/books");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/books", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT * FROM books WHERE user_id = $1", [
        req.user.id,
      ]);
      const books = result.rows;
      res.render("index.ejs", { books: books });
    } catch (error) {
      res.redirect("/login");
    }
  } else {
    res.redirect("/login");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/books",
    failureRedirect: "/login",
  }),
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password: ", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash],
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/new");
          });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.log("Error comparing passwords: ", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {
      console.log(error);
    }
  }),
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});
app.listen(port, () => {
  console.log(`Server running on port: ${port}`);
});
