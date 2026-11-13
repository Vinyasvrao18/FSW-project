const sqlite3 = require('sqlite3').verbose();
const fs = require('node:fs');
const path = require('node:path');

const databasePath = process.env.DB_PATH || path.join(__dirname, 'authguard.db');
if (databasePath !== ':memory:') {
  fs.mkdirSync(path.dirname(path.resolve(databasePath)), { recursive: true });
}

const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
const database = new sqlite3.Database(databasePath, error => {
  if (error) reportDatabaseError(error);
});

database.serialize(() => {
  database.exec(schema, error => {
    if (error) return reportDatabaseError(error);
    console.log('SQLite database ready:', databasePath);
    if (require.main === module) database.close();
  });
});

function reportDatabaseError(error) {
  console.error('Unable to initialize SQLite database at', databasePath, error.message);
  process.exit(1);
}

module.exports = database;
