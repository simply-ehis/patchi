import { db } from "../db/connection";

interface User {
  id: number;
  name: string;
  email: string;
}

export class UserService {
  async getAll(): Promise<User[]> {
    return db.query("SELECT * FROM users");
  }

  async getById(id: number): Promise<User | undefined> {
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
  }

  async create(data: Partial<User>): Promise<User> {
    return db.insert("users", data);
  }

  async update(id: number, data: Partial<User>): Promise<User> {
    return db.update("users", id, data);
  }

  async delete(id: number): Promise<void> {
    await db.delete("users", id);
  }

  // @ts-ignore -- TODO: fix this
  async search(query: any): Promise<any> {
    return db.query("SELECT * FROM users WHERE name LIKE ?", [`%${query}%`]);
  }
}

function legacyFormat(user: any): string {
  return `${user.name} <${user.email}>`;
}
