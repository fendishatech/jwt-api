const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();

// MIDDLE WARES
require("dotenv").config();
app.use(express.json());

// USER AUTH SECTION

const users = [
  {
    username: "kidus",
    email: "email@email.com",
    password: "password",
  },
];

const posts = [
  {
    username: "kidus",
    title: "software developer",
  },
  {
    username: "New",
    title: "Instructor",
  },
];

app.get("/users", (req, res) => {
  res.json(users);
});

app.post("/auth/register", async (req, res) => {
  // Registering a user
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const newUser = {
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    };
    users.push(newUser);

    res.json(users);
  } catch (error) {
    res.status(500).json();
  }
});

app.post("/auth/login", async (req, res) => {
  // ^ Auth done here
  const user = users.find((user) => user.email == req.body.email);

  if (user == null) {
    return res.status(400).send("user not Found");
  }

  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // Serialize this user
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1d",
      });
      res.status(200).json({ token: accessToken });
    } else {
      res.send("username or password is incorrect");
    }
  } catch (error) {
    res.status(500).json(error);
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token === null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
};

app.get("/posts", authenticateToken, (req, res) => {
  res.json(posts);
});

app.get("/posts/my", authenticateToken, (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.username));
});

app.listen(3000);
