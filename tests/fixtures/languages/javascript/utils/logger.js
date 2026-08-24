function log(message) {
  console.log(`[APP] ${message}`);
}

function error(message) {
  console.error(`[ERROR] ${message}`);
}

module.exports = { log, error };
