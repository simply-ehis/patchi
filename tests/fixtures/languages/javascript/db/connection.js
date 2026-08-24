const db = {
  query(sql, params) { return []; },
  insert(table, data) { return data; },
  update(table, id, data) { return data; },
  delete(table, id) { return true; },
};

module.exports = db;
