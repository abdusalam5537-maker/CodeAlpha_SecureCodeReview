// Sample Express app with intentionally introduced vulnerabilities, used
// only as demo input for the Secure Code Review tool. Do not deploy.

const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");

const app = express();

const API_SECRET = "sk_live_9fJ2kLp0qR7mZ8x";

app.get("/search", (req, res) => {
  const term = req.query.q;
  document.getElementById("results").innerHTML = "<p>Results for " + term + "</p>";
  res.send("ok");
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/render", (req, res) => {
  const name = req.query.name;
  document.write("<h1>Welcome " + name + "</h1>");
  res.send("ok");
});

app.get("/calc", (req, res) => {
  const expr = req.query.expr;
  const result = eval(expr);
  res.send(String(result));
});

function verifyToken(token) {
  return jwt.verify(token, API_SECRET, { algorithms: ["HS256", "none"] });
}

function makeSessionId() {
  return "sess_" + Math.random().toString(36).slice(2);
}

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/status", (req, res) => {
  fetch("http://payments.internal.example/status").then((r) => r.json());
  res.send("ok");
});

app.listen(3000);
