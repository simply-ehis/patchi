const express = require("express");
const path = require("path");
const { UserService } = require("./services/userService");
const { validateInput } = require("./middleware/validation");
const logger = require("./utils/logger");

const app = express();
app.use(express.json());

const userService = new UserService();

app.get("/users", async (req, res) => {
  const users = await userService.getAll();
  res.json({ items: users, count: users.length });
});

app.get("/users/:id", async (req, res) => {
  const user = await userService.getById(req.params.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json({ item: user });
});

app.post("/users", validateInput, async (req, res) => {
  const user = await userService.create(req.body);
  res.status(201).json({ item: user });
});

app.put("/users/:id", async (req, res) => {
  const user = await userService.update(req.params.id, req.body);
  res.json({ item: user });
});

app.delete("/users/:id", async (req, res) => {
  await userService.delete(req.params.id);
  res.json({ message: "Deleted" });
});

app.get("/search", (req, res) => {
  const query = req.query.q || "";
  res.json({ results: [] });
});

app.post("/upload", (req, res) => {
  const filePath = path.join("/uploads", req.body.filename);
  res.json({ path: filePath });
});

function unusedFunction() {
  return null;
}

module.exports = app;
