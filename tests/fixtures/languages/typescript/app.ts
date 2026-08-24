import express, { Request, Response } from "express";
import path from "path";
import { UserService } from "./services/userService";
import { validateInput } from "./middleware/validation";
import { log } from "./utils/logger";

const app = express();
app.use(express.json());

const userService = new UserService();

interface User {
  id: number;
  name: string;
  email: string;
}

app.get("/users", async (req: Request, res: Response) => {
  const users = await userService.getAll();
  res.json({ items: users, count: users.length });
});

app.get("/users/:id", async (req: Request, res: Response) => {
  const user = await userService.getById(Number(req.params.id));
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json({ item: user });
});

app.post("/users", validateInput, async (req: Request, res: Response) => {
  const user = await userService.create(req.body as Partial<User>);
  res.status(201).json({ item: user });
});

app.put("/users/:id", async (req: Request, res: Response) => {
  const user = await userService.update(Number(req.params.id), req.body);
  res.json({ item: user });
});

app.delete("/users/:id", async (req: Request, res: Response) => {
  await userService.delete(Number(req.params.id));
  res.json({ message: "Deleted" });
});

app.get("/search", (req: Request, res: Response) => {
  const query = (req.query.q as string) || "";
  res.json({ results: [] });
});

app.post("/upload", (req: Request, res: Response) => {
  const filePath = path.join("/uploads", req.body.filename);
  res.json({ path: filePath });
});

const unusedVariable: any = "I have type any";

function unusedFunction(): any {
  return null;
}

export default app;
