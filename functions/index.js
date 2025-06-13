const functions = require("firebase-functions");
const admin = require("firebase-admin");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

admin.initializeApp();

let appleKeys;

/**
 * Appleの公開鍵をキャッシュしながら取得する関数
 * @returns {Promise<Array>} Appleの公開鍵の配列
 */
async function getAppleKeys() {
  if (!appleKeys) {
    const res = await axios.get("https://appleid.apple.com/auth/keys");
    appleKeys = res.data.keys;
  }
  return appleKeys;
}

/**
 * AppleのIDトークンを検証する関数
 * @param {string} token - AppleのIDトークン
 * @param {string} nonce - ノンス値
 * @returns {object} 検証済みのペイロード
 */
async function verifyAppleToken(token, nonce) {
  const keys = await getAppleKeys();
  const decodedHeader = jwt.decode(token, { complete: true }).header;
  const key = keys.find((k) => k.kid === decodedHeader.kid);

  if (!key) {
    throw new Error("Unable to find matching JWK for token");
  }

  const publicKey = jwkToPem(key);
  const payload = jwt.verify(token, publicKey, {
    algorithms: ["RS256"],
    nonce: nonce
  });

  return payload;
}

exports.appleSignIn = functions.https.onRequest(async (req, res) => {
  try {
    const { identityToken, nonce } = req.body;
    const payload = await verifyAppleToken(identityToken, nonce);
    const uid = `apple:${payload.sub}`;

    const customToken = await admin.auth().createCustomToken(uid);
    res.json({ firebase_token: customToken });
  } catch (err) {
    console.error(err);
    res.status(401).send("Unauthorized");
  }
});

