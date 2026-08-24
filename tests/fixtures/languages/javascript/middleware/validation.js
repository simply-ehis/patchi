function validateInput(req, res, next) {
  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({ error: "Empty body" });
  }
  next();
}

function unusedMiddleware() {
  return true;
}

module.exports = { validateInput, unusedMiddleware };
