const db = require("../db/connection");

class UserService {
  async getAll() {
    return db.query("SELECT * FROM users");
  }

  async getById(id) {
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
  }

  async create(data) {
    return db.insert("users", data);
  }

  async update(id, data) {
    return db.update("users", id, data);
  }

  async delete(id) {
    return db.delete("users", id);
  }
}

function legacyFormat(user) {
  return `${user.name} <${user.email}>`;
}

module.exports = { UserService, legacyFormat };
