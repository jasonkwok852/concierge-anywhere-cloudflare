import { jwtVerify } from 'jose';

// 您的 Firebase 專案 ID
const FIREBASE_PROJECT_ID = 'cloudflare-concierge-anywhere'; 

// Firebase 公鑰的 JWKS (JSON Web Key Set) 端點
const JWKS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

// 用於快取從 Google 獲取的公鑰，避免重複請求
let cachedKeys = null;
let cachedAt = 0;
// 快取存活時間 (TTL): 1 小時 (毫秒)。Firebase JWKS 通常有 Cache-Control 頭部，但此為安全備用。
const CACHE_TTL = 3600000; 

/**
 * 從 Google 獲取 Firebase 公鑰，並進行快取。
 * @returns {Promise<Object>} 包含公鑰的物件。
 */
async function getPublicKeys() {
  const now = Date.now();
  // 如果快取存在且未過期，直接返回快取金鑰
  if (cachedKeys && now - cachedAt < CACHE_TTL) {
    return cachedKeys;
  }

  // 否則，從 JWKS_URL 重新獲取金鑰
  try {
    const res = await fetch(JWKS_URL);
    if (!res.ok) {
      console.error(`Failed to fetch Firebase public keys: ${res.status} ${res.statusText}`);
      throw new Error('Failed to fetch Firebase public keys');
    }
    cachedKeys = await res.json();
    cachedAt = now; // 更新快取時間
    return cachedKeys;
  } catch (error) {
    console.error('Error fetching public keys:', error);
    throw new Error('Failed to fetch Firebase public keys due to network or parsing error.');
  }
}

/**
 * 將 PEM (Privacy-Enhanced Mail) 格式的公鑰字串轉換為 ArrayBuffer。
 * @param {string} pem PEM 格式的公鑰字串。
 * @returns {ArrayBuffer} 轉換後的 ArrayBuffer。
 */
function pemToArrayBuffer(pem) {
  // 移除 PEM 標頭/標尾和換行符
  const b64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|\n|\r)/g, '');
  // 解碼 Base64
  const binary = atob(b64);
  // 轉換為 Uint8Array
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}

/**
 * Cloudflare Pages Functions 的入口點。
 * 負責驗證 Authorization 頭部中的 Firebase ID Token。
 * 此函數預期被 Cloudflare Access External Evaluation 調用。
 * @param {Object} context - Cloudflare Functions 上下文物件，包含 request。
 * @returns {Response} 驗證結果的回應，符合 Cloudflare Access 期望的 JSON 格式。
 */
export async function onRequest(context) {
  const { request } = context;
  const authHeader = request.headers.get('Authorization') || '';

  // 檢查 Authorization 頭部格式是否為 Bearer Token
  if (!authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ success: false, reason: 'Unauthorized: Missing or malformed Authorization header.' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  const token = authHeader.slice(7); // 提取 JWT Token 字串

  try {
    // 解析 JWT Header 以獲取 kid (Key ID)，用於查找對應的公鑰
    const [headerEncoded] = token.split('.');
    if (!headerEncoded) throw new Error('Invalid JWT format: missing header.');
    const header = JSON.parse(atob(headerEncoded));
    const kid = header.kid;
    if (!kid) throw new Error('No kid found in token header.');

    // 獲取公鑰並根據 kid 查找對應的金鑰
    const keys = await getPublicKeys();
    const pubKeyPEM = keys[kid];
    if (!pubKeyPEM) throw new Error(`Public key for kid "${kid}" not found.`);

    // 導入公鑰以供加密驗證 (RSASSA-PKCS1-v1_5, SHA-256)
    const pubKey = await crypto.subtle.importKey(
      'spki', 
      pemToArrayBuffer(pubKeyPEM),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, 
      false, 
      ['verify'] 
    );

    // 使用 jose 函式庫驗證 JWT 的簽名、發行者 (issuer) 和受眾 (audience)
    const { payload } = await jwtVerify(token, pubKey, {
      issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`, 
      audience: FIREBASE_PROJECT_ID, 
    });

    // 再次檢查 token 過期時間 (payload.exp)，儘管 jose 內部已檢查
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return new Response(JSON.stringify({ success: false, reason: 'Unauthorized: Token expired.' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 驗證成功：返回符合 Cloudflare Access External Evaluation 期望的 JSON 格式
    return new Response(JSON.stringify({
      success: true, // 必須為 true 表示驗證成功
      uid: payload.sub, // Firebase 用戶 ID
      email: payload.email || '', // 用戶 email，如果存在
      // common_name 字段常用於 Access Logs 和策略，優先使用 email
      common_name: payload.email || payload.sub 
    }), {
      status: 200, // 成功狀態碼
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (err) {
    // 捕獲所有驗證失敗的錯誤，並返回 401 Unauthorized
    // 在 Cloudflare Worker Logs 中記錄詳細錯誤，以便偵錯
    console.error('Firebase JWT verification failed:', err); 

    let userFacingReason = 'Unauthorized: Invalid token.';
    // 可以根據特定錯誤類型提供更精確的訊息（選填，取決於您的安全策略）
    if (err.name === 'JWTExpired') {
      userFacingReason = 'Unauthorized: Token expired.';
    } else if (err.name === 'JWSSignatureVerificationFailed') {
      userFacingReason = 'Unauthorized: Token signature invalid.';
    } else if (err.name === 'JWSInvalid') {
      userFacingReason = 'Unauthorized: Invalid JWT structure.';
    } else if (err.message.includes('No kid found')) { // 處理上面自定義的錯誤訊息
        userFacingReason = 'Unauthorized: Malformed token header.';
    }


    // 返回符合 Cloudflare Access External Evaluation 期望的失敗 JSON 格式
    return new Response(JSON.stringify({
      success: false, // 必須為 false 表示驗證失敗
      reason: userFacingReason // 錯誤原因
    }), {
      status: 401, // 失敗狀態碼
      headers: { 'Content-Type': 'application/json' },
    });
  }
}