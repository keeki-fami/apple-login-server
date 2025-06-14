require('dotenv').config();
const SECRET_KEY = process.env.SECRET_KEY;
const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.DB.HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


const app = express();
app.use(bodyParser.json());  // JSONのリクエストボディをパースする

let appleKeysCache;

/**
 * Appleの公開鍵をキャッシュしながら取得する関数
 */
async function getAppleKeys() {
  if (!appleKeysCache) {
    const res = await axios.get("https://appleid.apple.com/auth/keys");
    appleKeysCache = res.data.keys;
  }
  return appleKeysCache;
}

/**
 * AppleのIDトークンを検証する関数
 * @param {string} token - AppleのIDトークン
 * @param {string} nonce - ノンス値（SHA256済み）
 * @returns {object} 検証済みペイロード
 */
async function verifyAppleToken(token, nonce) {
  const keys = await getAppleKeys();
  const decodedHeader = jwt.decode(token, { complete: true }).header;
  const key = keys.find(k => k.kid === decodedHeader.kid);

  if (!key) {
    throw new Error("Apple public key not found");
  }

  const publicKey = jwkToPem(key);

  // JWTを検証する。nonceはクライアント側でSHA256済みの値を送っているので、そのまま比較
  const payload = jwt.verify(token, publicKey, {
    algorithms: ["RS256"],
    nonce
  });

  // ここでsub（ユーザー固有ID）があることを確認
  if (!payload.sub) {
    throw new Error("Invalid token payload: no sub");
  }

  return payload;
}

/**
 * Apple Sign In のルート
 */
app.post("/appleSignIn", async (req, res) => {
  try {
    const { identityToken, nonce } = req.body;
    if (!identityToken || !nonce) {
      return res.status(400).send("Missing identityToken or nonce");
    }

    // トークン検証
    const payload = await verifyAppleToken(identityToken, nonce);

　　const user = await findOrCreateUser(payload.sub);

    const token = generateJwt(user);

    res.json({ success: true, apple_sub: payload.sub });

    // Firebaseカスタムトークン発行

    // クライアントに返す
  } catch (error) {
    console.error("Apple Sign In Error:", error);
    res.status(401).send("Unauthorized");
  }
});

async function findOrCreateUser(appleSub) {
  const conn = await pool.getConnection();
  try {
    // 1. ユーザーがいるか検索
    const [rows] = await conn.query('SELECT * FROM users WHERE apple_sub = ?', [appleSub]);
    
    if (rows.length > 0) {
      // ユーザーが存在 → ログイン成功
      return rows[0];
    } else {
      // ユーザーがいなければ新規作成
      const [result] = await conn.query('INSERT INTO users (apple_sub) VALUES (?)', [appleSub]);
      return { id: result.insertId, apple_sub: appleSub };
    }
  } finally {
    conn.release();
  }
}

function generateJwt(user) {
  return jwt.sign(
    {
      sub: user.apple_sub, // or user.id
      iat: Math.floor(Date.now() / 1000), // 発行時間
    },
    SECRET_KEY,
    { expiresIn: '7d' } // 有効期限7日など
  );
}

// JWT認証ミドルウェア
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];  // "Bearer <token>" の形を想定
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// 認証必須APIの例：ユーザープロフィール取得
app.get('/user/profile', authenticateToken, async (req, res) => {
  try {
    const userSub = req.user.sub;
    const conn = await pool.getConnection();
    const [rows] = await conn.query('SELECT id, apple_sub FROM users WHERE apple_sub = ?', [userSub]);
    conn.release();

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ error: "Server error" });
  }
});


// サーバ起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

