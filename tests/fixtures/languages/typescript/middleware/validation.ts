import { Request, Response, NextFunction } from "express";

export function validateInput(req: Request, res: Response, next: NextFunction): void {
  if (!req.body || Object.keys(req.body).length === 0) {
    res.status(400).json({ error: "Empty body" });
    return;
  }
  next();
}

function unusedMiddleware(): boolean {
  return true;
}
