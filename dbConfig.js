// require('dotenv').config();
// const mysql = require('mysql2/promise');

// console.log('DB_HOST:', process.env.DB_HOST);
// console.log('DB_USER:', process.env.DB_USER);
// console.log('DB_DATABASE:', process.env.DB_DATABASE);
// console.log('DB_PORT:', process.env.DB_PORT);

// const dbConfig = {
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_DATABASE,
//   port: parseInt(process.env.DB_PORT) || 3306,
//   connectionLimit: 10,
//   debug: true,
// };

// const pool = mysql.createPool(dbConfig);

// pool
//   .getConnection()
//   .then(conn => {
//     console.log('Connected to MySQL');
//     conn.release();
//   })
//   .catch(err => {
//     console.error('Database connection failed:', err);
//     console.error('Error code:', err.code);
//     console.error('Error number:', err.errno);
//     process.exit(1);
//   });

// module.exports = { pool };









require('dotenv').config();
const mysql = require('mysql2/promise');

console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_USER:', process.env.DB_USER);
console.log('DB_DATABASE:', process.env.DB_DATABASE);
console.log('DB_PORT:', process.env.DB_PORT);

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: parseInt(process.env.DB_PORT) || 3306,
  connectionLimit: 10,
  debug: true,
  
};

const pool = mysql.createPool(dbConfig);

pool
  .getConnection()
  .then(conn => {
    console.log('Connected to MySQL');
    conn.release();
  })
  .catch(err => {
    console.error('Database connection failed:', err);
    console.error('Error code:', err.code);
    console.error('Error number:', err.errno);
    process.exit(1);
  });

module.exports = { pool };