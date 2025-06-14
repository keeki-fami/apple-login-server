require('dotenv').config(); // .envの読み込み
const mysql = require('mysql2/promise');

// 接続プールの作成
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

module.exports = pool;

