const express = require("express");
const admin = require("firebase-admin");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const bodyParser = require("body-parser");

admin.initializeApp();

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
    nonce: nonce
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

    // Firebase UIDにAppleのsubを利用
    const uid = `apple:${payload.sub}`;

    // Firebaseカスタムトークン発行
    const firebaseToken = await admin.auth().createCustomToken(uid);

    // クライアントに返す
    res.json({ firebase_token: firebaseToken });
  } catch (error) {
    console.error("Apple Sign In Error:", error);
    res.status(401).send("Unauthorized");
  }
});

// サーバ起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

